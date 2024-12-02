import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "or4nge",
  description: "Docs of or4nge team",
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    logo: '/or4nge.svg',

    siteTitle: 'or4nge',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'QuickStart', link: '/quick-start' },
      { text: 'Writeups', link: '/writeups' },
      { text: 'Members', link: '/members' },
    ],

    sidebar: {
      '/quick-start/': [
        {
          text: 'QuickStart',
          items: [
            { text: 'Index', link: '/guide/' },
          ]
        }
      ],

      '/writeups/': [
        {
          text: 'Writeups',
          items: [
            { text: 'Index', link: '/config/' },
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
