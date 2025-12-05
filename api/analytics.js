import { Redis } from '@upstash/redis';

let redis;
try {
  const redisUrl = process.env.KV_REST_API_URL;
  const redisToken = process.env.KV_REST_API_TOKEN;
  if (redisUrl && redisToken) {
    redis = new Redis({ url: redisUrl, token: redisToken });
  }
} catch (error) {
  console.error('Redis connection error:', error);
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

export default async function handler(req, res) {
  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  if (!redis) {
    return res.status(500).json({
      success: false,
      error: 'Redis not configured',
      totalQuestions: 0,
      uniqueQuestions: 0,
      questions: []
    });
  }
  
  try {
    const allQuestions = [];
    
    // Use SCAN instead of KEYS for better performance
    let cursor = '0';
    let iterations = 0;
    const maxIterations = 50; // Limit iterations to prevent timeout
    
    do {
      // Scan with a reasonable count
      const result = await redis.scan(cursor, {
        match: 'ast:question:*',
        count: 100
      });
      
      cursor = result[0];
      const keys = result[1];
      
      if (keys && keys.length > 0) {
        // Batch get the values for better performance
        const values = await Promise.all(
          keys.map(key => redis.get(key).catch(err => {
            console.error(`Error getting key ${key}:`, err);
            return null;
          }))
        );
        
        values.forEach(data => {
          if (data && data.question) {
            // Extract timestamp from key or use stored timestamp
            let timestamp = data.timestamp;
            
            if (!timestamp) {
              // Fallback to a default date if no timestamp
              timestamp = new Date('2025-11-01T00:00:00Z').toISOString();
            }
            
            allQuestions.push({
              question: data.question,
              category: data.category || 'Other Questions',
              icon: data.icon || '❓',
              timestamp: timestamp
            });
          }
        });
      }
      
      iterations++;
      
      // Break if we've iterated too many times to prevent timeout
      if (iterations >= maxIterations) {
        console.log(`Stopped after ${iterations} iterations to prevent timeout`);
        break;
      }
      
    } while (cursor !== '0' && cursor !== 0);
    
    // Sort by timestamp (most recent first)
    allQuestions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    const totalQuestions = allQuestions.length;
    const uniqueQuestions = new Set(
      allQuestions.map(q => q.question.toLowerCase().trim())
    ).size;
    
    console.log(`Successfully retrieved ${totalQuestions} total, ${uniqueQuestions} unique questions`);
    
    return res.status(200).json({
      success: true,
      totalQuestions,
      uniqueQuestions,
      questions: allQuestions,
      timestamp: new Date().toISOString(),
      note: iterations >= maxIterations ? 'Partial data - limited to prevent timeout' : 'Complete data'
    });
    
  } catch (error) {
    console.error('Error fetching analytics:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to fetch analytics',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
}
