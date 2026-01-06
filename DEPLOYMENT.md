# Deployment Guide for Render

## Render Configuration

### 1. Environment Variables
Set these in Render dashboard:
- `PORT` - Automatically set by Render (don't set manually)
- `GROQ_API_KEY` - (Optional) Your Groq API key for technical observations

### 2. Build Command
```
pip install -r requirements.txt && playwright install chromium && playwright install-deps chromium
```

### 3. Start Command
```
python main.py
```

### 4. Python Version
Set to: `3.10.12` (or use runtime.txt)

## Common Issues

### 500 Error - Playwright Not Installed
If you get a 500 error, it's likely because Playwright browsers aren't installed. Make sure your build command includes:
```
playwright install chromium && playwright install-deps chromium
```

### Timeout Issues
Render free tier has timeout limits. The diagnosis might timeout on slow websites. Consider:
- Increasing timeout in `diagnose_website.py`
- Using a paid Render plan for longer timeouts

### Memory Issues
Playwright can be memory-intensive. If you get memory errors:
- Use Render's paid plans with more RAM
- Or reduce concurrent requests

## Testing Locally Before Deploying

1. Test the app locally:
```bash
python main.py
```

2. Test with environment variable:
```bash
PORT=5000 python main.py
```

3. Verify Playwright works:
```bash
python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); p.chromium.launch(); print('Playwright OK')"
```

