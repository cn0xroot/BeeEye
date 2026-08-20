import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

import enCommon from './locales/en-US/common.json'
import enDevice from './locales/en-US/device.json'
import enAlert from './locales/en-US/alert.json'
import zhCommon from './locales/zh-CN/common.json'
import zhDevice from './locales/zh-CN/device.json'
import zhAlert from './locales/zh-CN/alert.json'

// Namespaces follow the layout in program.md §3.8.1.
//
// The backend never sends localized prose: a device category arrives as
// "camera" and an alert type as "beacon", and this table turns them into text.
// That is what stops a language switch from leaving half the page in the other
// language — there is no server-rendered string to be left behind.
i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    // Keyed by base language, not by region: load: 'languageOnly' resolves
    // "zh-CN"/"zh-TW" down to "zh" before looking a bundle up, so a "zh-CN"
    // key would never be found and every switch would fall back silently.
    resources: {
      en: { common: enCommon, device: enDevice, alert: enAlert },
      zh: { common: zhCommon, device: zhDevice, alert: zhAlert },
    },
    fallbackLng: 'zh',
    supportedLngs: ['en', 'zh'],
    load: 'languageOnly',
    nonExplicitSupportedLngs: true,
    ns: ['common', 'device', 'alert'],
    defaultNS: 'common',
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'BeeEye.lang',
      caches: ['localStorage'],
    },
  })

export default i18n
