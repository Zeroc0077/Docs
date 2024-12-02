import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "or4nge",
  description: "Docs of or4nge team",
  head: [
    ['link', { rel: 'apple-touch-icon', sizes: '180x180', href: '/favicon/apple-icon-180x180.png' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '192x192', href: '/favicon/android-icon-192x192.png' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '96x96', href: '/favicon/favicon-96x96.png' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '32x32', href: '/favicon/favicon-32x32.png' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '16x16', href: '/favicon/favicon-16x16.png' }],
    ['link', { rel: 'manifest', href: '/favicon/manifest.json' }]
  ],
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config

    logo: '/or4nge.svg',

    siteTitle: 'or4nge',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'QuickStart', link: '/quick-start/', activeMatch: '/quick-start/' },
      { text: 'Writeups', link: '/writeups/', activeMatch: '/writeups/' },
      { text: 'Members', link: '/members' },
    ],

    sidebar: {
      '/quick-start/': [
        {
          text: '前言',
          link: '/quick-start/',
        },
      ],

      '/writeups/': [
        {
          text: '总览',
          link: '/writeups/',
        },
        {
          text: '2024',
          items: [
            {
              text: '第八届强网杯全国网络安全挑战赛线上赛',
              link: '/writeups/2024/qwbs8'
            }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/or4nge-BUAA' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © or4nge'
    },

    lastUpdated: {
      text: 'Updated at',
      formatOptions: {
        dateStyle: 'full',
        timeStyle: 'medium'
      }
    }
  }
})
