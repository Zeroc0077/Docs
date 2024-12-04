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
    avatar: '/members/elegantcrazy.png',
    name: 'ElegantCrazy',
    title: 'Founder, Web 神',
    links: [
      { icon: 'github', link: 'https://github.com/ElegantCrazy' },
    ]
  },
  {
    avatar: '/members/s0uthwood.jpeg',
    name: 's0uthwood',
    title: 'Reverse 真神',
    links: [
      { icon: 'github', link: 'https://github.com/s0uthwood' },
    ]
  },
  {
    avatar: '/members/daidai.jpeg',
    name: 'daidai',
    title: 'Pwn 真神',
    links: [
      { icon: 'github', link: 'https://github.com/0xdaidai' },
    ]
  },
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
  {
    avatar: '/members/zzzccc.png',
    name: 'zzzccc',
    title: 'Reverse 神',
    links: [
      { icon: 'github', link: 'https://github.com/zzzcccyyyggg' },
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