// i18next configuration for RentReviews platform
const I18N_CONFIG = {
    // Supported languages
    supportedLanguages: ['en', 'es', 'zh', 'bn', 'hi'],

    // Language metadata
    languageNames: {
        en: 'English',
        es: 'Español',
        zh: '简体中文',
        bn: 'বাংলা',
        hi: 'हिन्दी'
    },

    // Default fallback language
    fallbackLanguage: 'en',

    // localStorage key for language preference
    storageKey: 'rentreviews_language',

    // Namespace mapping for each page
    namespaces: {
        'index.html': ['common', 'index'],
        'auth.html': ['common', 'auth'],
        'dashboard.html': ['common', 'dashboard'],
        'search.html': ['common', 'search'],
        'write-review.html': ['common', 'writeReview'],
        'add-property.html': ['common', 'addProperty'],
        'market-insights.html': ['common', 'marketInsights'],
        'verify-landlord.html': ['common', 'verifyLandlord'],
        'admin-seed-properties.html': ['common', 'adminSeed']
    }
};

// i18next initialization function
async function initI18n(currentPage) {
    const savedLanguage = localStorage.getItem(I18N_CONFIG.storageKey) ||
                         detectBrowserLanguage() ||
                         I18N_CONFIG.fallbackLanguage;

    const namespaces = I18N_CONFIG.namespaces[currentPage] || ['common'];

    try {
        await i18next
            .use(i18nextHttpBackend)
            .use(i18nextBrowserLanguageDetector)
            .init({
                lng: savedLanguage,
                fallbackLng: I18N_CONFIG.fallbackLanguage,
                ns: namespaces,
                defaultNS: 'common',
                debug: false, // Set to true for development
                backend: {
                    loadPath: './locales/{{lng}}/{{ns}}.json',
                },
                interpolation: {
                    escapeValue: false // Not needed for vanilla JS
                }
            });

        return i18next;
    } catch (error) {
        console.error('i18next initialization error:', error);
        throw error;
    }
}

// Detect browser language
function detectBrowserLanguage() {
    const browserLang = navigator.language || navigator.userLanguage;
    const langCode = browserLang.split('-')[0]; // 'en-US' -> 'en'

    return I18N_CONFIG.supportedLanguages.includes(langCode)
        ? langCode
        : I18N_CONFIG.fallbackLanguage;
}

// Language switcher helper
function changeLanguage(newLang) {
    if (!I18N_CONFIG.supportedLanguages.includes(newLang)) {
        console.error(`Unsupported language: ${newLang}`);
        return;
    }

    localStorage.setItem(I18N_CONFIG.storageKey, newLang);
    i18next.changeLanguage(newLang, () => {
        updatePageTranslations();
        updateHtmlLangAttribute(newLang);
    });
}

// Update HTML lang attribute for accessibility
function updateHtmlLangAttribute(lang) {
    document.documentElement.setAttribute('lang', lang);
}

// Update all translated elements on the page
function updatePageTranslations() {
    // Update elements with data-i18n attribute
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        element.textContent = i18next.t(key);
    });

    // Update elements with data-i18n-html attribute (for HTML content)
    document.querySelectorAll('[data-i18n-html]').forEach(element => {
        const key = element.getAttribute('data-i18n-html');
        element.innerHTML = i18next.t(key);
    });

    // Update placeholders
    document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
        const key = element.getAttribute('data-i18n-placeholder');
        element.placeholder = i18next.t(key);
    });

    // Update titles
    document.querySelectorAll('[data-i18n-title]').forEach(element => {
        const key = element.getAttribute('data-i18n-title');
        element.title = i18next.t(key);
    });

    // Update aria-labels for accessibility
    document.querySelectorAll('[data-i18n-aria]').forEach(element => {
        const key = element.getAttribute('data-i18n-aria');
        element.setAttribute('aria-label', i18next.t(key));
    });
}

// Helper function for dynamic translations with interpolation
function t(key, options = {}) {
    return i18next.t(key, options);
}

// Language selector functionality
function setupLanguageSelector() {
    const languageSelectorBtn = document.getElementById('languageSelectorBtn');
    const languageDropdown = document.getElementById('languageDropdown');
    const languageOptions = document.querySelectorAll('.language-option');

    if (!languageSelectorBtn || !languageDropdown) {
        console.warn('Language selector elements not found');
        return;
    }

    // Toggle dropdown
    languageSelectorBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        languageDropdown.classList.toggle('hidden');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (!document.getElementById('languageSelector').contains(e.target)) {
            languageDropdown.classList.add('hidden');
        }
    });

    // Handle language selection
    languageOptions.forEach(option => {
        option.addEventListener('click', () => {
            const selectedLang = option.getAttribute('data-lang');
            changeLanguage(selectedLang);

            // Update UI
            updateLanguageSelectorUI(selectedLang);
            languageDropdown.classList.add('hidden');
        });
    });

    // Initialize with current language
    const currentLang = i18next.language || I18N_CONFIG.fallbackLanguage;
    updateLanguageSelectorUI(currentLang);
}

// Update language selector UI
function updateLanguageSelectorUI(lang) {
    const currentLanguageName = document.getElementById('currentLanguageName');
    if (currentLanguageName) {
        currentLanguageName.textContent = I18N_CONFIG.languageNames[lang];
    }

    // Update checkmarks (if implemented)
    document.querySelectorAll('.language-check').forEach(check => {
        check.classList.add('hidden');
    });
    const selectedCheck = document.querySelector(`[data-lang="${lang}"] .language-check`);
    if (selectedCheck) {
        selectedCheck.classList.remove('hidden');
    }
}
