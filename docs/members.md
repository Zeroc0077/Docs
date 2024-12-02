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
    avatar: 'https://blog.zeroc0077.cn/images/avatar.jpeg',
    name: 'zeroc',
    title: '端茶倒水',
    links: [
      { icon: 'github', link: 'https://github.com/Zeroc0077' },
      { icon: 'twitter', link: 'https://x.com/zeroc45026434' }
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