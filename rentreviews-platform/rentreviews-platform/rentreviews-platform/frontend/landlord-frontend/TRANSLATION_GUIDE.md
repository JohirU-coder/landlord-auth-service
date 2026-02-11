# RentReviews Multi-Language Translation Guide

## Overview

This guide explains how to translate your RentReviews platform to 5 languages:
- 🇺🇸 English (en)
- 🇪🇸 Spanish (es)
- 🇨🇳 Chinese Simplified (zh)
- 🇧🇩 Bengali (bn)
- 🇮🇳 Hindi (hi)

## 📁 File Structure

```
locales/
├── en/          # English (source language)
│   ├── common.json
│   ├── index.json
│   ├── auth.json
│   ├── dashboard.json
│   ├── search.json
│   ├── writeReview.json
│   ├── addProperty.json
│   ├── marketInsights.json
│   ├── verifyLandlord.json
│   └── adminSeed.json
├── es/          # Spanish
├── zh/          # Chinese Simplified
├── bn/          # Bengali
└── hi/          # Hindi
```

## 🤖 Automated Translation with DeepL API

### Step 1: Get DeepL API Key

1. Visit [https://www.deepl.com/pro-api](https://www.deepl.com/pro-api)
2. Sign up for a **free account** (500,000 characters/month free)
3. Get your API key from the dashboard

### Step 2: Set Your API Key

**Option A: Environment Variable (Recommended)**
```bash
set DEEPL_API_KEY=your-api-key-here
node translate-with-deepl.js
```

**Option B: Edit the Script**
Open `translate-with-deepl.js` and replace:
```javascript
DEEPL_API_KEY: 'YOUR_DEEPL_API_KEY_HERE'
```
with:
```javascript
DEEPL_API_KEY: 'your-actual-api-key'
```

### Step 3: Run the Translation Script

```bash
node translate-with-deepl.js
```

The script will:
- ✅ Read all English JSON files
- ✅ Translate them to Spanish and Chinese using DeepL
- ✅ Save translated files to respective language folders
- ✅ Show progress for each file

**Note:** DeepL doesn't support Bengali and Hindi yet, so those will need manual translation or use Google Translate API instead.

## ⚠️ Important Notes

### DeepL Language Support

DeepL currently supports:
- ✅ Spanish (es) - Full support
- ✅ Chinese Simplified (zh) - Full support  
- ❌ Bengali (bn) - Not supported (use Google Translate or manual translation)
- ❌ Hindi (hi) - Not supported (use Google Translate or manual translation)

### Rate Limits

**DeepL Free Tier:**
- 500,000 characters/month
- Rate limit: ~10 requests/second

The script includes automatic rate limiting (100ms delay between requests).

### Translation Quality

- DeepL provides high-quality, context-aware translations
- Review translations for technical terms and brand names
- Some phrases may need manual adjustment for cultural relevance

## 🔄 Alternative: Google Translate API

For Bengali and Hindi, you can use Google Cloud Translation API:

1. Enable Google Cloud Translation API
2. Get API credentials
3. Modify the script to use Google Translate for bn/hi

## ✋ Manual Translation

If you prefer manual translation or need to translate Bengali/Hindi:

1. Open the English JSON file (e.g., `en/common.json`)
2. Copy it to the target language folder
3. Translate only the **values**, keep the **keys** in English
4. Maintain JSON structure and formatting

**Example:**

English (`en/common.json`):
```json
{
  "nav": {
    "features": "Features",
    "about": "About"
  }
}
```

Spanish (`es/common.json`):
```json
{
  "nav": {
    "features": "Características",
    "about": "Acerca de"
  }
}
```

## 🧪 Testing Translations

1. Start your local server:
   ```bash
   start-server.bat
   ```

2. Open http://localhost:8000/index.html

3. Click the language selector dropdown

4. Switch between languages to verify translations

5. Check that:
   - All text is translated
   - No translation keys (like "nav.features") are showing
   - Layout looks good with different text lengths
   - Special characters display correctly

## 📝 Translation Tips

1. **Keep it concise** - Some languages are longer than English
2. **Maintain tone** - Professional but friendly
3. **Cultural adaptation** - Adapt idioms and cultural references
4. **Technical terms** - Keep "RentReviews", "Dashboard", etc. consistent
5. **Currency** - Adjust currency symbols ($, €, ¥, etc.) as needed
6. **Date formats** - Consider different date formats per locale

## 🆘 Troubleshooting

### Translations not showing

1. Check that you're accessing via `http://localhost:8000` (not file://)
2. Verify JSON files are valid (no syntax errors)
3. Check browser console for errors
4. Clear browser cache and reload

### Missing translations

- Ensure all JSON files exist in all language folders
- Check that keys match exactly between files
- Verify i18n-config.js includes all namespaces

### Special characters broken

- Ensure files are saved as UTF-8 encoding
- Check that fonts support the character sets

## 📊 Translation Statistics

- **Total pages:** 9
- **Total translation files:** 10
- **Total translation keys:** ~350
- **Estimated translation time (manual):** 4-6 hours per language
- **Estimated translation time (DeepL):** 10-15 minutes (all languages)

## 🚀 Next Steps

After translation:
1. Test all pages in all languages
2. Have native speakers review translations
3. Collect user feedback
4. Iterate and improve translations
5. Set up continuous translation workflow for new features

---

**Questions?** Check the i18next documentation: https://www.i18next.com/
