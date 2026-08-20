import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

import enCommon from './locales/en-US/common.json'
import zhCommon from './locales/zh-CN/common.json'

// Every string the UI renders comes from here (F18) — nothing is hardcoded in
// a component. Protocol field names (ip.src, tls.handshake.type) are the one
// deliberate exception: they are filter syntax the user types, so translating
// them would make filters impossible to enter (program.md §3.12.5).
i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    // Resources are keyed by base language, not by region. With
    // load: 'languageOnly' i18next resolves "zh-CN" and "zh-TW" down to "zh"
    // before looking a bundle up, so keying these as "zh-CN" would make every
    // lookup miss and silently fall back to English — which is exactly what a
    // language switch that appears to do nothing looks like.
    resources: {
      en: { common: enCommon },
      zh: { common: zhCommon },
    },
    fallbackLng: 'en',
    supportedLngs: ['en', 'zh'],
    load: 'languageOnly',
    nonExplicitSupportedLngs: true,
    defaultNS: 'common',
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'BeeEye.lang',
      caches: ['localStorage'],
    },
  })

export default i18n
