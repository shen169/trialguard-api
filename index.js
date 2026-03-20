// Modified for Vercel serverless
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 简单的内存存储
const fingerprints = new Map();
const emailHistory = new Map();

function generateFingerprint(data) {
  const raw = `${data.userAgent || ''}|${data.screenResolution || ''}|${data.timezone || ''}`;
  return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 32);
}

function isTemporaryEmail(email) {
  const tempDomains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com', 'mailinator.com'];
  const domain = email.split('@')[1];
  return tempDomains.includes(domain);
}

app.post('/api/verify', (req, res) => {
  try {
    const { email, userAgent, screenResolution, timezone, ip } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const fingerprint = generateFingerprint({ userAgent, screenResolution, timezone });
    
    let riskScore = 0;
    const flags = [];

    // 检查设备指纹重复
    const fpData = fingerprints.get(fingerprint) || { count: 0 };
    if (fpData.count > 0) {
      riskScore += 30;
      flags.push('DEVICE_ALREADY_USED');
    }

    // 检查邮箱
    if (isTemporaryEmail(email)) {
      riskScore += 50;
      flags.push('TEMPORARY_EMAIL');
    }

    const emailData = emailHistory.get(email) || { count: 0 };
    if (emailData.count > 0) {
      riskScore += 20;
      flags.push('EMAIL_ALREADY_USED');
    }

    // 更新存储
    fpData.count++;
    fingerprints.set(fingerprint, fpData);

    emailData.count++;
    emailHistory.set(email, emailData);

    const isAllowed = riskScore < 70;
    
    res.json({
      allowed: isAllowed,
      riskScore,
      flags,
      fingerprint,
      message: isAllowed ? 'Verification passed' : 'High risk detected',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '0.1.0' });
});

// Vercel serverless handler
module.exports = app;

// Local development
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🛡️ TrialGuard API running on port ${PORT}`);
  });
}
