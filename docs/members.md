---
layout: page
---
<script setup>
import {
  VPTeamPage,
  VPTeamPageTitle,
  VPTeamMembers
} from 'vitepress/theme'

const members = [
  {
    avatar: '/members/zeroc.jpg',
    name: 'zeroc',
    title: '端茶倒水',
    links: [
      { icon: 'github', link: 'https://github.com/Zeroc0077' },
      { icon: 'twitter', link: 'https://x.com/zeroc45026434' }
    ]
  },
  {
    avatar: '/members/Eurus.jpg',
    name: 'Eurus',
    title: 'pwn 神',
    links: [
      { icon: 'github', link: 'https://github.com/AkaiEurus' },
    ]
  },
  {
    avatar: '/members/Joooooκ.jpeg',
    name: 'Joooooκ',
    title: 'Misc 神',
    links: [
      { icon: 'github', link: 'https://github.com/Joooook' },
    ]
  },
]
</script>

<VPTeamPage>
  <VPTeamPageTitle>
    <template #title>
      or4nge
    </template>
    <template #lead>
      The CTF team of BUAA CST
    </template>
  </VPTeamPageTitle>
  <VPTeamMembers
    :members="members"
  />
</VPTeamPage>