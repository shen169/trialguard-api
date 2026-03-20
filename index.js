const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 简单的内存存储 (生产环境应使用 Redis/PostgreSQL)
const fingerprints = new Map();
const emailHistory = new Map();
const ipHistory = new Map();

// 设备指纹生成
function generateFingerprint(data) {
  const {
    userAgent = '',
    screenResolution = '',
    timezone = '',
    languages = '',
    platform = '',
    canvas = '',
    webgl = ''
  } = data;
  
  const raw = `${userAgent}|${screenResolution}|${timezone}|${languages}|${platform}|${canvas}|${webgl}`;
  return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 32);
}

// 检测临时邮箱
function isTemporaryEmail(email) {
  const tempDomains = [
    'tempmail.com', '10minutemail.com', 'guerrillamail.com',
    'mailinator.com', 'throwawaymail.com', 'yopmail.com',
    'fakeemail.com', 'temp.inbox', 'mailnesia.com'
  ];
  const domain = email.split('@')[1];
  return tempDomains.includes(domain);
}

// 检测可疑 IP (简化版)
function isSuspiciousIP(ip) {
  // 检查是否是私有IP或常见代理
  const privateRanges = [
    /^127\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^192\.168\./
  ];
  return privateRanges.some(range => range.test(ip));
}

// 主验证 API
app.post('/api/verify', async (req, res) => {
  try {
    const {
      email,
      userAgent,
      screenResolution,
      timezone,
      languages,
      platform,
      canvas,
      webgl,
      ip = req.ip
    } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // 生成设备指纹
    const fingerprint = generateFingerprint({
      userAgent, screenResolution, timezone, languages, platform, canvas, webgl
    });

    // 风险评分
    let riskScore = 0;
    const flags = [];

    // 1. 检查设备指纹重复
    const fpData = fingerprints.get(fingerprint) || { count: 0, emails: new Set() };
    if (fpData.count > 0) {
      riskScore += 30;
      flags.push('DEVICE_ALREADY_USED');
    }
    if (fpData.emails.has(email) === false && fpData.count > 0) {
      riskScore += 40;
      flags.push('MULTIPLE_ACCOUNTS_SAME_DEVICE');
    }

    // 2. 检查邮箱
    if (isTemporaryEmail(email)) {
      riskScore += 50;
      flags.push('TEMPORARY_EMAIL');
    }

    const emailData = emailHistory.get(email) || { count: 0, fingerprints: new Set() };
    if (emailData.count > 0) {
      riskScore += 20;
      flags.push('EMAIL_ALREADY_USED');
    }

    // 3. 检查 IP
    if (isSuspiciousIP(ip)) {
      riskScore += 20;
      flags.push('SUSPICIOUS_IP');
    }

    const ipData = ipHistory.get(ip) || { count: 0, emails: new Set() };
    if (ipData.emails.size > 2) {
      riskScore += 25;
      flags.push('MULTIPLE_ACCOUNTS_SAME_IP');
    }

    // 更新存储
    fpData.count++;
    fpData.emails.add(email);
    fingerprints.set(fingerprint, fpData);

    emailData.count++;
    emailData.fingerprints.add(fingerprint);
    emailHistory.set(email, emailData);

    ipData.count++;
    ipData.emails.add(email);
    ipHistory.set(ip, ipData);

    // 返回结果
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
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 健康检查
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '0.1.0',
    uptime: process.uptime()
  });
});

// 统计信息
app.get('/stats', (req, res) => {
  res.json({
    fingerprints: fingerprints.size,
    uniqueEmails: emailHistory.size,
    uniqueIPs: ipHistory.size
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🛡️ TrialGuard API running on port ${PORT}`);
});

module.exports = app;
