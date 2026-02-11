/**
 * RentReviews Multi-Language Translation Script
 * Uses DeepL API to automatically translate all JSON files
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

// Configuration
const CONFIG = {
    DEEPL_API_KEY: process.env.DEEPL_API_KEY || 'f5224605-d4a2-40b3-b49f-681aa25ab1e3:fx',
    BASE_LOCALES_PATH: path.join(__dirname, 'locales'),
    SOURCE_LANGUAGE: 'en',
    TARGET_LANGUAGES: ['es', 'zh', 'bn', 'hi'],
    LANGUAGE_CODES: {
        'es': 'ES',      // Spanish
        'zh': 'ZH',      // Chinese (Simplified)
        'bn': 'EN',      // Bengali (will use EN as placeholder, DeepL doesn't support Bengali)
        'hi': 'EN'       // Hindi (will use EN as placeholder, DeepL doesn't support Hindi)
    }
};

// DeepL API Function
async function translateText(text, targetLang) {
    return new Promise((resolve, reject) => {
        const deeplLangCode = CONFIG.LANGUAGE_CODES[targetLang];
        
        // Skip translation if DeepL doesn't support the language
        if (deeplLangCode === 'EN') {
            console.log(`⚠️  DeepL doesn't support ${targetLang} - keeping English text`);
            resolve(text);
            return;
        }

        const postData = new URLSearchParams({
            text: text,
            target_lang: deeplLangCode,
            preserve_formatting: '1',
            formality: 'default'
        }).toString();

        const options = {
            hostname: 'api-free.deepl.com',
            port: 443,
            path: '/v2/translate',
            method: 'POST',
            headers: {
                'Authorization': `DeepL-Auth-Key ${CONFIG.DEEPL_API_KEY}`,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                try {
                    if (!data || data.trim() === '') {
                        reject(new Error(`Empty response from DeepL API (Status: ${res.statusCode})`));
                        return;
                    }

                    const response = JSON.parse(data);

                    // Check for API errors
                    if (response.message) {
                        reject(new Error(`DeepL API Error: ${response.message}`));
                        return;
                    }

                    if (response.translations && response.translations[0]) {
                        resolve(response.translations[0].text);
                    } else {
                        reject(new Error(`Invalid DeepL response: ${JSON.stringify(response).substring(0, 200)}`));
                    }
                } catch (error) {
                    reject(new Error(`Failed to parse DeepL response: ${error.message}. Data: ${data.substring(0, 200)}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.write(postData);
        req.end();
    });
}

// Recursively translate JSON object
async function translateJSON(obj, targetLang, path = '') {
    const translated = {};
    
    for (const [key, value] of Object.entries(obj)) {
        const currentPath = path ? `${path}.${key}` : key;
        
        if (typeof value === 'string') {
            // Translate string values
            try {
                console.log(`  Translating: ${currentPath}`);
                translated[key] = await translateText(value, targetLang);
                
                // Rate limiting: wait 500ms between requests to avoid hitting limits
                await new Promise(resolve => setTimeout(resolve, 500));
            } catch (error) {
                console.error(`  ❌ Error translating ${currentPath}:`, error.message);
                translated[key] = value; // Keep original on error
            }
        } else if (typeof value === 'object' && value !== null) {
            // Recursively translate nested objects
            translated[key] = await translateJSON(value, targetLang, currentPath);
        } else {
            // Keep non-string values as-is
            translated[key] = value;
        }
    }
    
    return translated;
}

// Get all JSON files from source language folder
function getTranslationFiles() {
    const enPath = path.join(CONFIG.BASE_LOCALES_PATH, CONFIG.SOURCE_LANGUAGE);
    return fs.readdirSync(enPath)
        .filter(file => file.endsWith('.json'));
}

// Main translation function
async function translateAllFiles() {
    console.log('🌍 RentReviews Translation Script');
    console.log('='.repeat(50));
    console.log(`Source Language: ${CONFIG.SOURCE_LANGUAGE}`);
    console.log(`Target Languages: ${CONFIG.TARGET_LANGUAGES.join(', ')}`);
    console.log('='.repeat(50));
    console.log('');

    // Check API key
    if (CONFIG.DEEPL_API_KEY === 'YOUR_DEEPL_API_KEY_HERE') {
        console.error('❌ Error: Please set your DeepL API key!');
        console.log('');
        console.log('Options:');
        console.log('1. Set environment variable: DEEPL_API_KEY=your_key_here');
        console.log('2. Edit this script and replace YOUR_DEEPL_API_KEY_HERE');
        console.log('');
        console.log('Get your free API key at: https://www.deepl.com/pro-api');
        process.exit(1);
    }

    const files = getTranslationFiles();
    console.log(`Found ${files.length} translation files:\n`, files.map(f => `  - ${f}`).join('\n'));
    console.log('');

    for (const targetLang of CONFIG.TARGET_LANGUAGES) {
        console.log(`\n📝 Translating to ${targetLang.toUpperCase()}...`);
        console.log('-'.repeat(50));

        for (const file of files) {
            console.log(`\n📄 Processing: ${file}`);
            
            const sourcePath = path.join(CONFIG.BASE_LOCALES_PATH, CONFIG.SOURCE_LANGUAGE, file);
            const targetPath = path.join(CONFIG.BASE_LOCALES_PATH, targetLang, file);

            try {
                // Read source JSON
                const sourceData = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
                
                // Translate
                const translatedData = await translateJSON(sourceData, targetLang);
                
                // Ensure target directory exists
                const targetDir = path.dirname(targetPath);
                if (!fs.existsSync(targetDir)) {
                    fs.mkdirSync(targetDir, { recursive: true });
                }
                
                // Write translated JSON
                fs.writeFileSync(
                    targetPath,
                    JSON.stringify(translatedData, null, 2),
                    'utf8'
                );
                
                console.log(`  ✅ Successfully translated ${file} to ${targetLang}`);
            } catch (error) {
                console.error(`  ❌ Error processing ${file}:`, error.message);
            }
        }
    }

    console.log('\n' + '='.repeat(50));
    console.log('✅ Translation complete!');
    console.log('='.repeat(50));
}

// Run the script
translateAllFiles().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
