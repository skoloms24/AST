import OpenAI from "openai";
import { Redis } from "@upstash/redis";

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Initialize Redis
let redis;
try {
  const redisUrl = process.env.KV_REST_API_URL;
  const redisToken = process.env.KV_REST_API_TOKEN;

  if (redisUrl && redisToken) {
    redis = new Redis({
      url: redisUrl,
      token: redisToken
    });
    console.log('✅ Redis connected successfully');
  } else {
    console.log('⚠️ Redis credentials not found - analytics disabled');
  }
} catch (error) {
  console.error('❌ Redis connection error:', error);
}

// ===== SECURITY CONFIGURATION =====
const SECURITY_CONFIG = {
  MAX_MESSAGE_LENGTH: 200,
  RATE_LIMIT: {
    MAX_REQUESTS: 10,
    WINDOW_MS: 60000, // 1 minute
    BAN_DURATION_MS: 300000 // 5 minutes
  }
};

// Rate limiting storage
const rateLimitStore = new Map();
const bannedIPs = new Map();

// Get client IP
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['x-real-ip'] || 
         req.connection?.remoteAddress || 
         'unknown';
}

// Check if IP is banned
function isIPBanned(ip) {
  if (bannedIPs.has(ip)) {
    const banExpiry = bannedIPs.get(ip);
    if (Date.now() < banExpiry) {
      return true;
    }
    bannedIPs.delete(ip);
  }
  return false;
}

// Rate limiting check
function checkRateLimit(ip) {
  const now = Date.now();
  
  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + SECURITY_CONFIG.RATE_LIMIT.WINDOW_MS });
    return { allowed: true, remaining: SECURITY_CONFIG.RATE_LIMIT.MAX_REQUESTS - 1 };
  }
  
  const record = rateLimitStore.get(ip);
  
  if (now > record.resetTime) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + SECURITY_CONFIG.RATE_LIMIT.WINDOW_MS });
    return { allowed: true, remaining: SECURITY_CONFIG.RATE_LIMIT.MAX_REQUESTS - 1 };
  }
  
  if (record.count >= SECURITY_CONFIG.RATE_LIMIT.MAX_REQUESTS) {
    bannedIPs.set(ip, now + SECURITY_CONFIG.RATE_LIMIT.BAN_DURATION_MS);
    console.log(`🚫 IP banned for rate limit violation: ${ip}`);
    return { allowed: false, remaining: 0, banned: true };
  }
  
  record.count++;
  return { allowed: true, remaining: SECURITY_CONFIG.RATE_LIMIT.MAX_REQUESTS - record.count };
}

// Prompt injection detection
function detectPromptInjection(message) {
  const suspiciousPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|directions)/i,
    /disregard\s+(previous|prior|above)\s+(instructions|prompts|rules)/i,
    /forget\s+(everything|all)\s+(you\s+)?(were\s+told|learned|instructions)/i,
    /new\s+(instructions|rules|prompt):/i,
    /system\s*:\s*you\s+are\s+now/i,
    /your\s+new\s+(role|instructions|task)\s+is/i,
    /\[SYSTEM\]/i,
    /\<\|im_start\|\>/i,
    /pretend\s+(you're|you\s+are|to\s+be)\s+(a\s+)?(different|new)/i,
    /act\s+as\s+if\s+you/i,
    /reveal\s+your\s+(instructions|prompt|system)/i,
    /what\s+(are|were)\s+your\s+(original\s+)?(instructions|prompts)/i
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(message)) {
      console.log(`🚨 Prompt injection detected: ${message.substring(0, 100)}`);
      return true;
    }
  }
  return false;
}

// CORS configuration - IMPORTANT: Set ALLOWED_ORIGIN in your environment variables
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

const corsHeaders = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

// In-memory cache for responses
const responseCache = new Map();
const CACHE_TTL = 3600000; // 1 hour
const SIMILARITY_THRESHOLD = 0.6;

// IMPORTANT: Store your assistant ID here after first creation
// You can get this from OpenAI dashboard or the console log on first run
const ASSISTANT_ID = process.env.ASSISTANT_ID || null;

function normalizeMessage(message) {
  return message.toLowerCase()
    .trim()
    .replace(/[?!.,]/g, '')
    .replace(/\s+/g, ' ');
}

function findSimilarInCache(message) {
  const normalized = normalizeMessage(message);
  const words = normalized.split(' ');
  
  // Exact match
  if (responseCache.has(normalized)) {
    const cached = responseCache.get(normalized);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      console.log('✅ Exact cache hit');
      return cached;
    }
  }
  
  // Fuzzy match
  for (const [cachedKey, cachedValue] of responseCache.entries()) {
    if (Date.now() - cachedValue.timestamp >= CACHE_TTL) continue;
    
    const cachedWords = cachedKey.split(' ');
    const commonWords = words.filter(w => w.length > 3 && cachedWords.includes(w));
    const similarity = commonWords.length / Math.max(words.length, cachedWords.length);
    
    if (similarity >= SIMILARITY_THRESHOLD) {
      console.log(`✅ Fuzzy cache hit (${Math.round(similarity * 100)}% similarity)`);
      return cachedValue;
    }
  }
  
  return null;
}

function isActualQuestion(message) {
  const text = message.toLowerCase().trim();
  
  if (text.length < 5) return false;
  
  const nonQuestions = [
    'yes', 'ye', 'no', 'ok', 'okay', 'thanks', 'thank you', 
    'nope', 'yep', 'yeah', 'nah', 'sure', 'fine', 'alright',
    'hello', 'hi', 'hey', 'bye', 'goodbye', 'skip',
    'basic', 'intermediate', 'advanced', 'none', 'idk', 'dunno'
  ];
  if (nonQuestions.includes(text)) return false;
  
  // Filter out standalone numbers or year responses
  if (/^\d+$/.test(text) || /^\d+\s*(years?|yrs?)$/.test(text)) return false;
  
  const questionIndicators = [
    'how', 'what', 'when', 'where', 'why', 'who', 'which', 
    'can i', 'do i', 'should i', 'is the', 'is there', 'are there', 
    'will', 'would', 'could', 'does', 'am i', 'may i', '?',
    'tell me', 'explain', 'describe', 'salary', 'pay', 'services',
    'help', 'hiring', 'recruiting', 'talent', 'candidate', 'job'
  ];
  
  return questionIndicators.some(indicator => text.includes(indicator));
}

function categorizeQuestion(question) {
  const q = question.toLowerCase();

  // Services / What We Do
  if (
    q.includes("what do you do") ||
    q.includes("services") ||
    q.includes("what services") ||
    q.includes("help with") ||
    q.includes("specialize") ||
    q.includes("offerings")
  ) {
    return { category: "Services / What We Do", icon: "🎯" };
  }

  // Recruiting / Hiring Process
  if (
    q.includes("recruiting") ||
    q.includes("recruitment") ||
    q.includes("hiring process") ||
    q.includes("how to hire") ||
    q.includes("find candidates") ||
    q.includes("sourcing")
  ) {
    return { category: "Recruiting / Hiring Process", icon: "🔍" };
  }

  // Industries / Specialization
  if (
    q.includes("industry") ||
    q.includes("industries") ||
    q.includes("specialize in") ||
    q.includes("sector") ||
    q.includes("field")
  ) {
    return { category: "Industries / Specialization", icon: "🏢" };
  }

  // Pricing / Fees
  if (
    q.includes("price") ||
    q.includes("pricing") ||
    q.includes("cost") ||
    q.includes("fee") ||
    q.includes("how much") ||
    q.includes("charge")
  ) {
    return { category: "Pricing / Fees", icon: "💰" };
  }

  // Timeline / Process Duration
  if (
    q.includes("how long") ||
    q.includes("timeline") ||
    q.includes("time frame") ||
    q.includes("duration") ||
    q.includes("how fast") ||
    q.includes("quickly")
  ) {
    return { category: "Timeline / Process Duration", icon: "⏱️" };
  }

  // Contact / Get Started
  if (
    q.includes("contact") ||
    q.includes("reach") ||
    q.includes("get started") ||
    q.includes("talk to") ||
    q.includes("speak with") ||
    q.includes("schedule") ||
    q.includes("consultation")
  ) {
    return { category: "Contact / Get Started", icon: "📞" };
  }

  // Location / Service Area
  if (
    q.includes("where") ||
    q.includes("location") ||
    q.includes("area") ||
    q.includes("regions") ||
    q.includes("serve")
  ) {
    return { category: "Location / Service Area", icon: "📍" };
  }

  // About / Company Info
  if (
    q.includes("about") ||
    q.includes("who are") ||
    q.includes("background") ||
    q.includes("experience") ||
    q.includes("history")
  ) {
    return { category: "About / Company Info", icon: "ℹ️" };
  }

  // Candidate Quality / Screening
  if (
    q.includes("quality") ||
    q.includes("screening") ||
    q.includes("vetting") ||
    q.includes("qualified") ||
    q.includes("background check")
  ) {
    return { category: "Candidate Quality / Screening", icon: "✅" };
  }

  // Job Seekers / Candidates
  if (
    q.includes("looking for job") ||
    q.includes("candidate") ||
    q.includes("job seeker") ||
    q.includes("apply") ||
    q.includes("resume")
  ) {
    return { category: "Job Seekers / Candidates", icon: "👔" };
  }

  return { category: "Other Questions", icon: "❓" };
}

async function logAnalytics(question) {
  if (!redis) {
    console.log('⚠️ Redis not available, skipping analytics');
    return;
  }
  
  if (!isActualQuestion(question)) {
    console.log('⚠️ Skipping non-question:', question);
    return;
  }
  
  try {
    const { category, icon } = categorizeQuestion(question);
    const analyticsKey = `ast:question:${Date.now()}`;
    
    await redis.set(analyticsKey, {
      question: question,
      category: category,
      icon: icon,
      timestamp: new Date().toISOString(),
    });
    
    // Expire after 2 years
    await redis.expire(analyticsKey, 730 * 24 * 60 * 60);
    
    console.log(`✅ Analytics logged: "${question}" → ${icon} ${category}`);
  } catch (error) {
    console.error('❌ Analytics logging error:', error);
  }
}

async function getOrCreateAssistant() {
  // If ASSISTANT_ID is set in environment, use it
  if (ASSISTANT_ID) {
    console.log('✅ Using existing assistant:', ASSISTANT_ID);
    return ASSISTANT_ID;
  }
  
  // Otherwise create a new one (only happens once)
  // NO INSTRUCTIONS HERE - you control them in OpenAI dashboard
  try {
    console.log('⚠️ No ASSISTANT_ID found, creating new assistant...');
    const assistant = await openai.beta.assistants.create({
      name: "All-Star Talent Recruiting Assistant",
      model: "gpt-4o-mini",
      tools: [{ type: "file_search" }]
    });
    
    console.log('✅ Created new assistant:', assistant.id);
    console.log('⚠️ IMPORTANT: Add this to your Vercel environment variables:');
    console.log(`   ASSISTANT_ID=${assistant.id}`);
    console.log('⚠️ Then update the assistant instructions in OpenAI dashboard at platform.openai.com');
    
    return assistant.id;
  } catch (error) {
    console.error("❌ Error creating assistant:", error);
    throw error;
  }
}

function removeCitations(text) {
  let cleaned = text.replace(/【\d+:\d+†[^】]+】/g, '');
  cleaned = cleaned.replace(/\[\d+:\d+†[^\]]+\]/g, '');
  cleaned = cleaned.replace(/\[\d+\]/g, '');
  cleaned = cleaned.replace(/†[^\s]+\.pdf/g, '');
  cleaned = cleaned.replace(/\s+/g, ' ').trim();
  return cleaned;
}

function formatBulletPoints(text) {
  // Detect bullet points that are inline (separated by " - ")
  // Convert them to proper line breaks
  
  let formatted = text;
  
  // If there are multiple " - " in sequence, it's likely a bullet list
  const bulletCount = (text.match(/ - /g) || []).length;
  
  if (bulletCount >= 2) {
    // Find the section with bullets and format it
    formatted = text.replace(/(:|\.) - /g, '$1\n\n- ');
    // Replace remaining " - " with line breaks
    formatted = formatted.replace(/ - ([A-Z])/g, '\n- $1');
  }
  
  return formatted;
}

export default async function handler(req, res) {
  // Set CORS headers
  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // ===== SECURITY CHECKS =====
    
    // Get client IP
    const clientIP = getClientIP(req);
    console.log(`📍 Request from IP: ${clientIP}`);

    // Check if IP is banned
    if (isIPBanned(clientIP)) {
      console.log(`🚫 Banned IP attempted access: ${clientIP}`);
      return res.status(429).json({
        error: 'Too many requests. Please try again later.',
        success: false
      });
    }

    // Rate limiting check
    const rateLimitResult = checkRateLimit(clientIP);
    if (!rateLimitResult.allowed) {
      console.log(`🚫 Rate limit exceeded for IP: ${clientIP}`);
      return res.status(429).json({
        error: 'Rate limit exceeded. Please wait a few minutes before trying again.',
        success: false
      });
    }

    // Validate API key
    if (!process.env.OPENAI_API_KEY) {
      console.error("❌ OPENAI_API_KEY not found");
      return res.status(500).json({ 
        error: 'Server configuration error',
        success: false
      });
    }

    const { message, threadId } = req.body;

    if (!message || typeof message !== 'string') {
      return res.status(400).json({ 
        error: 'Valid message is required',
        success: false 
      });
    }

    // Character limit check
    if (message.length > SECURITY_CONFIG.MAX_MESSAGE_LENGTH) {
      console.log(`🚫 Message too long: ${message.length} characters from ${clientIP}`);
      return res.status(400).json({
        error: `Message too long. Please keep your question under ${SECURITY_CONFIG.MAX_MESSAGE_LENGTH} characters.`,
        success: false
      });
    }

    // Prompt injection check
    if (detectPromptInjection(message)) {
      console.log(`🚨 Prompt injection attempt blocked from ${clientIP}`);
      return res.status(400).json({
        error: 'Invalid message format. Please rephrase your question.',
        success: false
      });
    }

    // Log analytics
    await logAnalytics(message);

    // Check cache
    const cached = findSimilarInCache(message);
    if (cached) {
      console.log("✅ Returning cached response");
      return res.status(200).json({
        reply: cached.reply,
        threadId: cached.threadId,
        scrollToForm: cached.scrollToForm,
        cached: true,
        success: true
      });
    }

    // Get or create assistant
    const assistantId = await getOrCreateAssistant();

    // Get or create thread
    let thread;
    if (threadId) {
      thread = { id: threadId };
      console.log('✅ Using existing thread:', threadId);
    } else {
      thread = await openai.beta.threads.create();
      console.log('✅ Created new thread:', thread.id);
    }

    // Add message to thread
    await openai.beta.threads.messages.create(thread.id, {
      role: "user",
      content: message
    });

    // Run assistant
    const run = await openai.beta.threads.runs.createAndPoll(thread.id, {
      assistant_id: assistantId
    });

    if (run.status === 'completed') {
      const messages = await openai.beta.threads.messages.list(thread.id);
      const lastMessage = messages.data[0];
      let reply = lastMessage.content[0].text.value;
      
      // Clean up citations
      reply = removeCitations(reply);
      
      // Format bullet points properly
      reply = formatBulletPoints(reply);
      
      // Check for form scroll trigger
      const shouldScrollToForm = reply.includes('[SCROLL_TO_FORM]');
      const cleanReply = reply.replace('[SCROLL_TO_FORM]', '').trim();

      // Cache response
      const normalizedKey = normalizeMessage(message);
      responseCache.set(normalizedKey, {
        reply: cleanReply,
        threadId: thread.id,
        scrollToForm: shouldScrollToForm,
        timestamp: Date.now()
      });

      // Limit cache size
      if (responseCache.size > 100) {
        const oldestKey = responseCache.keys().next().value;
        responseCache.delete(oldestKey);
      }

      return res.status(200).json({ 
        reply: cleanReply,
        threadId: thread.id,
        scrollToForm: shouldScrollToForm,
        cached: false,
        success: true 
      });
    } else {
      console.error("❌ Run failed with status:", run.status);
      return res.status(500).json({ 
        error: 'Failed to get response from assistant',
        success: false
      });
    }

  } catch (error) {
    console.error('❌ Error in chat handler:', error);
    return res.status(500).json({ 
      error: 'Failed to process request',
      details: error.message,
      success: false
    });
  }
}
