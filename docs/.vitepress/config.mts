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
        {
          text: '各方向入门文档',
          items: [
            {
              text: 'Web 安全',
              link: '/quick-start/web'
            },
            {
              text: 'Pwn 二进制安全',
              link: '/quick-start/pwn'
            },
            {
              text: 'Reverse 逆向工程',
              link: '/quick-start/re'
            },
            {
              text: 'Crypto 密码学',
              link: '/quick-start/crypto'
            },
            {
              text: 'Misc 杂项',
              link: '/quick-start/misc'
            },
          ]
        }
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
      text: 'Last Updated at',
      formatOptions: {
        dateStyle: 'short',
        timeStyle: 'medium'
      }
    }
  }
})
