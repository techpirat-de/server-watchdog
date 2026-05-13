'use strict';

const RISK_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

async function check(report, config) {
  const result = {
    name: 'aiReview',
    status: 'skipped',
    risk: 'low',
    findings: [],
    metrics: {},
    response: null,
  };

  if (!config.ENABLE_AI_REVIEW || config.ENABLE_AI_REVIEW === 'false') {
    result.findings.push({ type: 'disabled', message: 'AI review disabled via ENABLE_AI_REVIEW' });
    return result;
  }

  if (RISK_RANK[report.overallRisk] < RISK_RANK['medium']) {
    result.findings.push({ type: 'skipped', message: `Risk level ${report.overallRisk} is below threshold for AI review` });
    return result;
  }

  if (!config.OPENAI_API_KEY) {
    result.status = 'error';
    result.findings.push({ type: 'config_error', message: 'OPENAI_API_KEY not set' });
    return result;
  }

  try {
    // Dynamic import for ESM fetch compatibility
    const fetch = (await import('node-fetch')).default;

    const prompt = buildPrompt(report);

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: config.OPENAI_MODEL || 'gpt-4o',
        temperature: 0.2,
        max_tokens: 800,
        messages: [
          {
            role: 'system',
            content: 'You are a server security analyst. Respond ONLY with valid JSON matching the schema provided. No markdown, no explanations outside JSON.',
          },
          { role: 'user', content: prompt },
        ],
      }),
      timeout: 30000,
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const raw = data.choices?.[0]?.message?.content?.trim();
    if (!raw) throw new Error('Empty response from OpenAI');

    const parsed = JSON.parse(raw);

    result.status = 'ok';
    result.risk = parsed.risk || report.overallRisk;
    result.response = parsed;
    result.findings.push({ type: 'ai_assessment', message: parsed.summary });

  } catch (err) {
    result.status = 'error';
    result.findings.push({ type: 'ai_error', message: `AI review failed: ${err.message}` });
  }

  return result;
}

function buildPrompt(report) {
  // Mask any accidental sensitive data
  const safe = JSON.stringify(report, null, 2).replace(/(api[_-]?key|password|token|secret)["\s:=]+\S+/gi, '$1: [REDACTED]');

  return `Analyze this server monitoring report and respond with JSON only.

Report:
${safe}

Required JSON response schema:
{
  "risk": "low|medium|high|critical",
  "summary": "One sentence summary of the situation",
  "likely_cause": "Most probable cause of the findings",
  "recommended_actions": ["Action 1", "Action 2"],
  "notify": true,
  "urgency": "normal|urgent"
}`;
}

module.exports = { check };
