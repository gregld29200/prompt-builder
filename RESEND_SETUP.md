# Resend Email Setup for Forgot Password

## Issue Diagnosis

The forgot password system shows "Email sent!" but no email is received. This is typically due to Resend configuration issues.

## Required Setup Steps

### 1. Resend API Key
```bash
# Set the Resend API key as a Cloudflare secret
wrangler secret put RESEND_API_KEY
# Enter your Resend API key when prompted
```

### 2. Domain Verification in Resend
1. **Login to Resend Dashboard**: https://resend.com/domains
2. **Add Domain**: `teachinspire.com`
3. **Verify DNS Records**: Add the required DNS records to your domain
4. **Wait for Verification**: Domain must show "Verified" status

### 3. Environment Variables
Update your Cloudflare Pages environment variables:

```bash
# Frontend URL for reset links
FRONTEND_URL=https://prompt.teachinspire.me

# Resend API Key (set via wrangler secret)
RESEND_API_KEY=your_resend_api_key_here
```

## Common Issues & Solutions

### ❌ **"RESEND_API_KEY environment variable is not set"**
**Solution**: Run `wrangler secret put RESEND_API_KEY` and deploy

### ❌ **"Domain not verified" error from Resend**
**Solution**: 
1. Go to Resend dashboard
2. Verify `teachinspire.com` domain
3. Add required DNS records

### ❌ **403 Forbidden from Resend API**
**Solution**: Check your API key permissions in Resend dashboard

### ❌ **Emails go to spam**
**Solution**: 
1. Add SPF record: `v=spf1 include:_spf.resend.com ~all`
2. Add DKIM records (provided by Resend)
3. Add DMARC record: `v=DMARC1; p=quarantine;`

## Testing the Setup

### 1. Check Cloudflare Logs
```bash
# View live logs
wrangler tail --format pretty
```

### 2. Test Reset Flow
1. Go to: `https://prompt.teachinspire.me/app?lang=fr`
2. Click "Mot de passe oublié"
3. Enter a valid email address
4. Check console logs for errors

### 3. Expected Log Output
```
✅ Sending reset email with URL: https://prompt.teachinspire.me/app?token=abc123&lang=fr
✅ Sending email with data: { from: 'TeachInspire <noreply@teachinspire.com>', to: ['user@example.com'], subject: '...' }
✅ Reset email sent successfully to: user@example.com
✅ Resend response: {"id":"abc123-def456"}
```

### 4. Error Log Examples
```
❌ RESEND_API_KEY environment variable is not set
❌ Resend API error: { status: 403, statusText: 'Forbidden', response: 'Invalid API key' }
❌ Resend API error: { status: 400, statusText: 'Bad Request', response: 'Domain not verified' }
```

## Deployment Commands

```bash
# 1. Set the API key
wrangler secret put RESEND_API_KEY

# 2. Deploy the updated function
wrangler pages deploy

# 3. Check logs
wrangler tail
```

## Backup Email Configuration

If Resend continues to fail, you can temporarily switch to a different email service by modifying the `sendResetEmail` function in `/functions/api/auth/forgot-password.ts`.

## Support

If issues persist:
1. Check Resend dashboard for delivery logs
2. Verify domain DNS records
3. Check Cloudflare Pages function logs
4. Test with a simple email service like SendGrid or Nodemailer