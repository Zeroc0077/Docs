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
    avatar: '/members/pil10w.jpg',
    name: 'pil10w',
    title: 'Web 神',
    links: [
      { icon: 'github', link: 'https://github.com/g00dfe11ow' },
    ]
  },
  {
    avatar: '/members/daidai.jpeg',
    name: 'daidai',
    title: 'Pwn 神',
    links: [
      { icon: 'github', link: 'https://github.com/0xdaidai' },
    ]
  },
  {
    avatar: '/members/SSGSS.png',
    name: 'SSGSS',
    title: 'Previous Captain, Web 神',
    links: [
      { icon: 'github', link: 'https://github.com/FYHSSGSS' },
    ]
  },
  {
    avatar: '/members/s0uthwood.jpeg',
    name: 's0uthwood',
    title: 'Reverse 神',
    links: [
      { icon: 'github', link: 'https://github.com/s0uthwood' },
    ]
  },
  {
    avatar: '/members/triplewings.png',
    name: 'triplewings',
    title: 'Pwn & 零知识 神',
    links: [
      { icon: 'github', link: 'https://github.com/kfxp12138' },
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