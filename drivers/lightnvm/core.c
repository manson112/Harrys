/*
 * Copyright (C) 2015 IT University of Copenhagen. All rights reserved.
 * Initial release: Matias Bjorling <m@bjorling.me>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */

#include <linux/bitmap.h>
#include <linux/lightnvm.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched/sysctl.h>
#include <linux/sem.h>
#include <linux/types.h>

static LIST_HEAD(nvm_tgt_types); // include/linux/list.h
static DECLARE_RWSEM(nvm_tgtt_lock);
static LIST_HEAD(nvm_devices);
static DECLARE_RWSEM(nvm_lock);

/* Map between virtual and physical channel and lun */
// 가상 채널과 물리 채널
struct nvm_ch_map {
  int ch_off;
  int num_lun;
  int *lun_offs;
};

//
struct nvm_dev_map {
  struct nvm_ch_map *chnls;
  int num_ch;
};

// device로부터 nvm target을 찾음
// pos= 리스트의 헤드가 가리키는 리스트가 있는 구조체 ; 다시 자기 자신에게
// 돌아오기 전까지(리스트는 순환구조이므로) ;  pos를 리스트의 next가 가리키는
// 있는 구조체로 바꿔줌 #define list_for_each_entry(pos, head, member)
//    for (pos = list_entry((head)->next, typeof(*pos), member);   &pos->member
//    != (head); pos = list_entry(pos->member.next, typeof(*pos), member))

// #define list_entry(ptr, type, member)
//    container_of(ptr, type, member)

// ptr(구조체 내부의 임의의 포인터 값)을 가지고 구조체의 주소를 찾아 type*(type:
// ptr을 멤버로 갖는 자료구조 형)으로 반환 member : 구조체 내에서 ptr의 멤버
// 이름 #define container_of(ptr, type, member) ({
//        const typeof( ((type *)0)->member ) *__mptr = (ptr);
//        (type *)( (char *)__mptr - offsetof(type,member) );
// })

static struct nvm_target *nvm_find_target(struct nvm_dev *dev,
                                          const char *name) {
  struct nvm_target *tgt;

  //  struct nvm_target {
  // 		struct list_head list;
  // 		struct nvm_tgt_dev *dev;
  // 		struct nvm_tgt_type *type;
  // 		struct gendisk *disk;
  //  };

  // struct nvm_tgt_dev {
  // 	/* Device information */
  // 	struct nvm_geo geo;

  // 	/* Base ppas for target LUNs */
  // 	struct ppa_addr *luns;

  // 	struct request_queue *q;

  // 	struct nvm_dev *parent;
  // 	void *map;
  // };

  //주어진 nvm_dev를 포함하는 struct인 nvm_target의 이름과  주어진 이름이 같다면
  //해당 nvm_target을 반환하고 없다면 아니면 NULL을 반환
  list_for_each_entry(tgt, &dev->targets,
                      list) if (!strcmp(name, tgt->disk->disk_name)) return tgt;

  return NULL;
}

// 1. 세마포어와 뮤텍스
// Critical Section을 정의하기 위해서 세마포어를 사용한다.
// 일반적으로 P와 V 함수 쌍을 사용하는데, linux 에서는 P함수는 “down”, V 함수를
// “up”이라 부른다. 단일 세마포어(공유 자원 개수를 1개로 정의)로 사용할 때
// 뮤텍스(Mutual Exclusion)라 부른다.

// nvm_devices->targets에 있는 target 중 name과 같은 target이 있다면 true를 반환
static bool nvm_target_exists(const char *name) {
  struct nvm_dev *dev;
  struct nvm_target *tgt;
  bool ret = false;

  //쓰기 전용 세마포어 값을 감소시킴
  down_write(&nvm_lock);
  list_for_each_entry(dev, &nvm_devices, devices) {
    // nvm_devices list 에 존재하는 devices에 대해 mutex_lock을 해주고
    mutex_lock(&dev->mlock);
    list_for_each_entry(tgt, &dev->targets, list) {
      // dev의 target list에 있는 각각의 target의 name과 주어진 name이 같다면
      // true
      if (!strcmp(name, tgt->disk->disk_name)) {
        ret = true;
        mutex_unlock(&dev->mlock);
        goto out;
      }
    }
    mutex_unlock(&dev->mlock);
  }

out:
  //쓰기 전용 세마포어 값 증가
  up_write(&nvm_lock);
  return ret;
}

// test_and_set_bit(int nr, volatile unsigned long *addr) :
// 해당 비트를 셋 하고(1), 해당 비트가 1(set) 이었으면 1 리턴, 해당 비트가
// 0(clear) 이었으면 0 리턴

// lun을 reserve 하는데 주어진 lun_begin ~ lun_end 사이에서 이미 set 된 비트가
// 있다면 다시 set했던 비트를 clear 하고 -EBUSY 리턴
static int nvm_reserve_luns(struct nvm_dev *dev, int lun_begin, int lun_end) {
  int i;

  for (i = lun_begin; i <= lun_end; i++) {
    if (test_and_set_bit(i, dev->lun_map)) {
      pr_err("nvm: lun %d already allocated\n", i);
      goto err;
    }
  }

  return 0;
err:
  while (--i >= lun_begin)
    clear_bit(i, dev->lun_map);

  return -EBUSY;
}

// WARN_ON : 콜 스택 표시
// lun_map의 어떤 lun에서 오류가 났는지 콜 스택을 출력하여 확인한다.
static void nvm_release_luns_err(struct nvm_dev *dev, int lun_begin,
                                 int lun_end) {
  int i;

  for (i = lun_begin; i <= lun_end; i++)
    WARN_ON(!test_and_clear_bit(i, dev->lun_map));
}

// nvm_dev 에서 주어진 nvm_tgt_dev를 삭제한다.
static void nvm_remove_tgt_dev(struct nvm_tgt_dev *tgt_dev, int clear) {
  struct nvm_dev *dev = tgt_dev->parent;
  // tgt_dev의 물리, 가상 map을 가져온다.
  struct nvm_dev_map *dev_map = tgt_dev->map;
  int i, j;

  for (i = 0; i < dev_map->num_ch; i++) {
    // dev_map에서 i번 째 channel의 map을 가져온다.
    struct nvm_ch_map *ch_map = &dev_map->chnls[i];
    // lun_offs를 구하고, ch_offset을 i에 더해 ch를 구한다.
    int *lun_offs = ch_map->lun_offs;
    int ch = i + ch_map->ch_off;

    if (clear) {
      for (j = 0; j < ch_map->num_lun; j++) {
        // j에 lun_offs을 더해 lun을 찾고
        int lun = j + lun_offs[j];
        //채널 * dev lun 개수 + lun을 해서 lunid를 구한다.
        int lunid = (ch * dev->geo.num_lun) + lun;

        // lun_map 에서 lunid에 해당하는 비트를 clear하고 콜 스택을 출력
        WARN_ON(!test_and_clear_bit(lunid, dev->lun_map));
      }
    }

    // lun offset을 할당 해제
    kfree(ch_map->lun_offs);
  }

  // dev_map 할당 해제
  kfree(dev_map->chnls);
  kfree(dev_map);

  // tgt_dev 할당 해제
  kfree(tgt_dev->luns);
  kfree(tgt_dev);
}

// nvm_tgt_dev 생성
static struct nvm_tgt_dev *
nvm_create_tgt_dev(struct nvm_dev *dev, u16 lun_begin, u16 lun_end, u16 op) {
  struct nvm_tgt_dev *tgt_dev = NULL;
  struct nvm_dev_map *dev_rmap = dev->rmap;
  struct nvm_dev_map *dev_map;
  struct ppa_addr *luns;
  // lun 수
  int num_lun = lun_end - lun_begin + 1;
  int luns_left = num_lun;
  //채널 수 = lun 수 / dev의 geo.num_lun수
  int num_ch = num_lun / dev->geo.num_lun;
  //남는 채널 수
  int num_ch_mod = num_lun % dev->geo.num_lun;

  int bch = lun_begin / dev->geo.num_lun;
  int blun = lun_begin % dev->geo.num_lun;
  int lunid = 0;
  int lun_balanced = 1;
  int sec_per_lun, prev_num_lun;
  int i, j;

  num_ch = (num_ch_mod == 0) ? num_ch : num_ch + 1;

  // GFP_KERNEL : 동적 메모리 할당이 항상 성공하도록 요구
  // GFP_ATOMIC : 커널에 할당 가능한 메모리가 있으면 무조건 할당, 없으면 즉시
  // NULL 반환,
  //              프로세스가 잠드는 경우는 없지만 할당에 실패한 경우를 대비해
  //              예외처리 필수
  // GFP_DMA : 연속된 물리 메모리를 할당받을 때 사용 (물리적 공간이 나뉘어
  // 있으면 DMA컨트롤러에서는 사용할 수 없음)
  dev_map = kmalloc(sizeof(struct nvm_dev_map), GFP_KERNEL);
  if (!dev_map)
    goto err_dev;

  // kcalloc — allocate memory for an array. The memory is set to zero.
  // static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
  // {
  // if (size != 0 && n > ULONG_MAX / size)
  // return NULL;
  // return __kmalloc(n * size, flags | __GFP_ZERO);
  // }
  dev_map->chnls = kcalloc(num_ch, sizeof(struct nvm_ch_map), GFP_KERNEL);
  if (!dev_map->chnls)
    goto err_chnls;

  luns = kcalloc(num_lun, sizeof(struct ppa_addr), GFP_KERNEL);
  if (!luns)
    goto err_luns;

  prev_num_lun = (luns_left > dev->geo.num_lun) ? dev->geo.num_lun : luns_left;
  for (i = 0; i < num_ch; i++) {
    struct nvm_ch_map *ch_rmap = &dev_rmap->chnls[i + bch];
    int *lun_roffs = ch_rmap->lun_offs;
    struct nvm_ch_map *ch_map = &dev_map->chnls[i];
    int *lun_offs;
    int luns_in_chnl =
        (luns_left > dev->geo.num_lun) ? dev->geo.num_lun : luns_left;

    if (lun_balanced && prev_num_lun != luns_in_chnl)
      lun_balanced = 0;

    ch_map->ch_off = ch_rmap->ch_off = bch;
    ch_map->num_lun = luns_in_chnl;

    lun_offs = kcalloc(luns_in_chnl, sizeof(int), GFP_KERNEL);
    if (!lun_offs)
      goto err_ch;

    for (j = 0; j < luns_in_chnl; j++) {
      luns[lunid].ppa = 0;
      luns[lunid].a.ch = i;
      luns[lunid++].a.lun = j;

      lun_offs[j] = blun;
      lun_roffs[j + blun] = blun;
    }

    ch_map->lun_offs = lun_offs;

    /* when starting a new channel, lun offset is reset */
    blun = 0;
    luns_left -= luns_in_chnl;
  }

  dev_map->num_ch = num_ch;

  tgt_dev = kmalloc(sizeof(struct nvm_tgt_dev), GFP_KERNEL);
  if (!tgt_dev)
    goto err_ch;

  /* Inherit device geometry from parent */
  memcpy(&tgt_dev->geo, &dev->geo, sizeof(struct nvm_geo));

  /* Target device only owns a portion of the physical device */
  tgt_dev->geo.num_ch = num_ch;
  tgt_dev->geo.num_lun = (lun_balanced) ? prev_num_lun : -1;
  tgt_dev->geo.all_luns = num_lun;
  tgt_dev->geo.all_chunks = num_lun * dev->geo.num_chk;

  tgt_dev->geo.op = op;

  sec_per_lun = dev->geo.clba * dev->geo.num_chk;
  tgt_dev->geo.total_secs = num_lun * sec_per_lun;

  tgt_dev->q = dev->q;
  tgt_dev->map = dev_map;
  tgt_dev->luns = luns;
  tgt_dev->parent = dev;

  return tgt_dev;
err_ch:
  while (--i >= 0)
    kfree(dev_map->chnls[i].lun_offs);
  kfree(luns);
err_luns:
  kfree(dev_map->chnls);
err_chnls:
  kfree(dev_map);
err_dev:
  return tgt_dev;
}

static const struct block_device_operations nvm_fops = {
    .owner = THIS_MODULE,
};

//주어진 name과 같은 이름의 target을 찾는다
static struct nvm_tgt_type *__nvm_find_target_type(const char *name) {
  struct nvm_tgt_type *tt;

  list_for_each_entry(tt, &nvm_tgt_types,
                      list) if (!strcmp(name, tt->name)) return tt;

  return NULL;
}

//주어진 name과 같은 이름의 target을 찾는다
static struct nvm_tgt_type *nvm_find_target_type(const char *name) {
  struct nvm_tgt_type *tt;

  down_write(&nvm_tgtt_lock);
  tt = __nvm_find_target_type(name);
  up_write(&nvm_tgtt_lock);

  return tt;
}

static int nvm_config_check_luns(struct nvm_geo *geo, int lun_begin,
                                 int lun_end) {
  // lun_begin과 lun_end가 맞지 않거나 lun_end의 범위가 모든 lun범위보다 크면
  // 오류를 출력한다.
  if (lun_begin > lun_end || lun_end >= geo->all_luns) {
    pr_err("nvm: lun out of bound (%u:%u > %u)\n", lun_begin, lun_end,
           geo->all_luns - 1);
    return -EINVAL;
  }
  //해당하지 않으면 0을 리턴
  return 0;
}

static int __nvm_config_simple(struct nvm_dev *dev,
                               struct nvm_ioctl_create_simple *s) {
  struct nvm_geo *geo = &dev->geo;

  // lun_begin과 lun_end가 모두 -1이면 모든 lun을 check함
  if (s->lun_begin == -1 && s->lun_end == -1) {
    s->lun_begin = 0;
    s->lun_end = geo->all_luns - 1;
  }

  return nvm_config_check_luns(geo, s->lun_begin, s->lun_end);
}

// nvm config extended 설정
static int __nvm_config_extended(struct nvm_dev *dev,
                                 struct nvm_ioctl_create_extended *e) {
  // e의 lun_begin과 lun_end가 모두 0xFFFF 이면 모든 e의 모든 lun config check
  if (e->lun_begin == 0xFFFF && e->lun_end == 0xFFFF) {
    e->lun_begin = 0;
    e->lun_end = dev->geo.all_luns - 1;
  }

  // e의 op가 0xFFFF이면 op를 NVM_TARGET_DEFAULT_OP로 지정
  // e의 OP가 OP 범위를 벗어나면 오류를 리턴
  /* op not set falls into target's default */
  if (e->op == 0xFFFF) {
    e->op = NVM_TARGET_DEFAULT_OP;
  } else if (e->op < NVM_TARGET_MIN_OP || e->op > NVM_TARGET_MAX_OP) {
    pr_err("nvm: invalid over provisioning value\n");
    return -EINVAL;
  }

  return nvm_config_check_luns(&dev->geo, e->lun_begin, e->lun_end);
}

// nvm_target을 생성
static int nvm_create_tgt(struct nvm_dev *dev,
                          struct nvm_ioctl_create *create) {
  struct nvm_ioctl_create_extended e;
  struct request_queue *tqueue;
  struct gendisk *tdisk;
  struct nvm_tgt_type *tt;
  struct nvm_target *t;
  struct nvm_tgt_dev *tgt_dev;
  void *targetdata;
  int ret;

  // conf type에 따라 ret 를 설정 (simple or extended)
  switch (create->conf.type) {
  case NVM_CONFIG_TYPE_SIMPLE:
    ret = __nvm_config_simple(dev, &create->conf.s);
    //에러가 발생하면 return
    if (ret)
      return ret;

    // lun_begin, lun_end를 extend에 설정 후
    e.lun_begin = create->conf.s.lun_begin;
    e.lun_end = create->conf.s.lun_end;
    e.op = NVM_TARGET_DEFAULT_OP;
    break;
  case NVM_CONFIG_TYPE_EXTENDED:
    ret = __nvm_config_extended(dev, &create->conf.e);
    if (ret)
      return ret;

    e = create->conf.e;
    break;
  default:
    pr_err("nvm: config type not valid\n");
    return -EINVAL;
  }

  tt = nvm_find_target_type(create->tgttype);
  if (!tt) {
    pr_err("nvm: target type %s not found\n", create->tgttype);
    return -EINVAL;
  }

  // nvm_target이 이미 존재하면 오류
  if (nvm_target_exists(create->tgtname)) {
    pr_err("nvm: target name already exists (%s)\n", create->tgtname);
    return -EINVAL;
  }

  // lun을 예약
  ret = nvm_reserve_luns(dev, e.lun_begin, e.lun_end);
  if (ret)
    return ret;

  // target을 할당
  t = kmalloc(sizeof(struct nvm_target), GFP_KERNEL);
  if (!t) {
    ret = -ENOMEM;
    goto err_reserve;
  }

  // target device 생성
  tgt_dev = nvm_create_tgt_dev(dev, e.lun_begin, e.lun_end, e.op);
  if (!tgt_dev) {
    pr_err("nvm: could not create target device\n");
    ret = -ENOMEM;
    goto err_t;
  }

  // gendisk 구조체 생성
  tdisk = alloc_disk(0);
  if (!tdisk) {
    ret = -ENOMEM;
    goto err_dev;
  }
  // struct request_queue *blk_alloc_queue_node(gfp_t gfp_mask, int node_id)
  // {
  //     struct request_queue *q;
  // 	int err;

  // 	q = kmem_cache_alloc_node(blk_requestq_cachep, gfp_mask | __GFP_ZERO,
  // node_id); 	if (!q) 		return NULL;
  //  (ida_simple_get : 여러개의 request queue가 있을 때 각각의 고유한 id를
  //  만들어주는 함수)
  // 	q->id = ida_simple_get(&blk_queue_ida, 0, 0, gfp_mask);
  // 	if (q->id < 0)
  // 		goto fail_q;
  // }
  // request queue를 만들어준다.
  tqueue = blk_alloc_queue_node(GFP_KERNEL, dev->q->node, NULL);
  if (!tqueue) {
    ret = -ENOMEM;
    goto err_disk;
  }
  blk_queue_make_request(tqueue, tt->make_rq);

  // disk_name을 tgtname으로 변경 후 몇가지 옵션 지정
  strlcpy(tdisk->disk_name, create->tgtname, sizeof(tdisk->disk_name));
  tdisk->flags = GENHD_FL_EXT_DEVT;
  tdisk->major = 0;
  tdisk->first_minor = 0;
  tdisk->fops = &nvm_fops;
  tdisk->queue = tqueue;

  // targetdata init
  targetdata = tt->init(tgt_dev, tdisk, create->flags);
  if (IS_ERR(targetdata)) {
    ret = PTR_ERR(targetdata);
    goto err_init;
  }

  tdisk->private_data = targetdata;
  tqueue->queuedata = targetdata;

  blk_queue_max_hw_sectors(tqueue, (dev->geo.csecs >> 9) * NVM_MAX_VLBA);

  set_capacity(tdisk, tt->capacity(targetdata));
  add_disk(tdisk);

  if (tt->sysfs_init && tt->sysfs_init(tdisk)) {
    ret = -ENOMEM;
    goto err_sysfs;
  }

  t->type = tt;
  t->disk = tdisk;
  t->dev = tgt_dev;

  mutex_lock(&dev->mlock);
  list_add_tail(&t->list, &dev->targets);
  mutex_unlock(&dev->mlock);

  __module_get(tt->owner);

  return 0;
err_sysfs:
  if (tt->exit)
    tt->exit(targetdata, true);
err_init:
  blk_cleanup_queue(tqueue);
  tdisk->queue = NULL;
err_disk:
  put_disk(tdisk);
err_dev:
  nvm_remove_tgt_dev(tgt_dev, 0);
err_t:
  kfree(t);
err_reserve:
  nvm_release_luns_err(dev, e.lun_begin, e.lun_end);
  return ret;
}

// nvm_target 제거
static void __nvm_remove_target(struct nvm_target *t, bool graceful) {
  struct nvm_tgt_type *tt = t->type;
  struct gendisk *tdisk = t->disk;
  struct request_queue *q = tdisk->queue;

  del_gendisk(tdisk);
  blk_cleanup_queue(q);

  if (tt->sysfs_exit)
    tt->sysfs_exit(tdisk);

  if (tt->exit)
    tt->exit(tdisk->private_data, graceful);

  nvm_remove_tgt_dev(t->dev, 1);
  put_disk(tdisk);
  module_put(t->type->owner);

  list_del(&t->list);
  kfree(t);
}

/**
 * nvm_remove_tgt - Removes a target from the media manager
 * @dev:	device
 * @remove:	ioctl structure with target name to remove.
 *
 * Returns:
 * 0: on success
 * 1: on not found
 * <0: on error
 */
static int nvm_remove_tgt(struct nvm_dev *dev,
                          struct nvm_ioctl_remove *remove) {
  struct nvm_target *t;

  mutex_lock(&dev->mlock);
  t = nvm_find_target(dev, remove->tgtname);
  if (!t) {
    mutex_unlock(&dev->mlock);
    return 1;
  }
  __nvm_remove_target(t, true);
  mutex_unlock(&dev->mlock);

  return 0;
}

static int nvm_register_map(struct nvm_dev *dev) {
  struct nvm_dev_map *rmap;
  int i, j;

  rmap = kmalloc(sizeof(struct nvm_dev_map), GFP_KERNEL);
  if (!rmap)
    goto err_rmap;

  rmap->chnls = kcalloc(dev->geo.num_ch, sizeof(struct nvm_ch_map), GFP_KERNEL);
  if (!rmap->chnls)
    goto err_chnls;

  for (i = 0; i < dev->geo.num_ch; i++) {
    struct nvm_ch_map *ch_rmap;
    int *lun_roffs;
    int luns_in_chnl = dev->geo.num_lun;

    ch_rmap = &rmap->chnls[i];

    ch_rmap->ch_off = -1;
    ch_rmap->num_lun = luns_in_chnl;

    lun_roffs = kcalloc(luns_in_chnl, sizeof(int), GFP_KERNEL);
    if (!lun_roffs)
      goto err_ch;

    for (j = 0; j < luns_in_chnl; j++)
      lun_roffs[j] = -1;

    ch_rmap->lun_offs = lun_roffs;
  }

  dev->rmap = rmap;

  return 0;
err_ch:
  while (--i >= 0)
    kfree(rmap->chnls[i].lun_offs);
err_chnls:
  kfree(rmap);
err_rmap:
  return -ENOMEM;
}

static void nvm_unregister_map(struct nvm_dev *dev) {
  struct nvm_dev_map *rmap = dev->rmap;
  int i;

  for (i = 0; i < dev->geo.num_ch; i++)
    kfree(rmap->chnls[i].lun_offs);

  kfree(rmap->chnls);
  kfree(rmap);
}

static void nvm_map_to_dev(struct nvm_tgt_dev *tgt_dev, struct ppa_addr *p) {
  struct nvm_dev_map *dev_map = tgt_dev->map;
  struct nvm_ch_map *ch_map = &dev_map->chnls[p->a.ch];
  int lun_off = ch_map->lun_offs[p->a.lun];

  p->a.ch += ch_map->ch_off;
  p->a.lun += lun_off;
}

static void nvm_map_to_tgt(struct nvm_tgt_dev *tgt_dev, struct ppa_addr *p) {
  struct nvm_dev *dev = tgt_dev->parent;
  struct nvm_dev_map *dev_rmap = dev->rmap;
  struct nvm_ch_map *ch_rmap = &dev_rmap->chnls[p->a.ch];
  int lun_roff = ch_rmap->lun_offs[p->a.lun];

  p->a.ch -= ch_rmap->ch_off;
  p->a.lun -= lun_roff;
}

// ppa를 device addr로 변경
static void nvm_ppa_tgt_to_dev(struct nvm_tgt_dev *tgt_dev,
                               struct ppa_addr *ppa_list, int nr_ppas) {
  int i;

  for (i = 0; i < nr_ppas; i++) {
    nvm_map_to_dev(tgt_dev, &ppa_list[i]);
    ppa_list[i] = generic_to_dev_addr(tgt_dev->parent, ppa_list[i]);
  }
}

static void nvm_ppa_dev_to_tgt(struct nvm_tgt_dev *tgt_dev,
                               struct ppa_addr *ppa_list, int nr_ppas) {
  int i;

  for (i = 0; i < nr_ppas; i++) {
    ppa_list[i] = dev_to_generic_addr(tgt_dev->parent, ppa_list[i]);
    nvm_map_to_tgt(tgt_dev, &ppa_list[i]);
  }
}

static void nvm_rq_tgt_to_dev(struct nvm_tgt_dev *tgt_dev, struct nvm_rq *rqd) {
  if (rqd->nr_ppas == 1) {
    nvm_ppa_tgt_to_dev(tgt_dev, &rqd->ppa_addr, 1);
    return;
  }

  nvm_ppa_tgt_to_dev(tgt_dev, rqd->ppa_list, rqd->nr_ppas);
}

static void nvm_rq_dev_to_tgt(struct nvm_tgt_dev *tgt_dev, struct nvm_rq *rqd) {
  if (rqd->nr_ppas == 1) {
    nvm_ppa_dev_to_tgt(tgt_dev, &rqd->ppa_addr, 1);
    return;
  }

  nvm_ppa_dev_to_tgt(tgt_dev, rqd->ppa_list, rqd->nr_ppas);
}

int nvm_register_tgt_type(struct nvm_tgt_type *tt) {
  int ret = 0;

  down_write(&nvm_tgtt_lock);
  if (__nvm_find_target_type(tt->name))
    ret = -EEXIST;
  else
    list_add(&tt->list, &nvm_tgt_types);
  up_write(&nvm_tgtt_lock);

  return ret;
}
EXPORT_SYMBOL(nvm_register_tgt_type);

void nvm_unregister_tgt_type(struct nvm_tgt_type *tt) {
  if (!tt)
    return;

  down_write(&nvm_tgtt_lock);
  list_del(&tt->list);
  up_write(&nvm_tgtt_lock);
}
EXPORT_SYMBOL(nvm_unregister_tgt_type);

void *nvm_dev_dma_alloc(struct nvm_dev *dev, gfp_t mem_flags,
                        dma_addr_t *dma_handler) {
  return dev->ops->dev_dma_alloc(dev, dev->dma_pool, mem_flags, dma_handler);
}
EXPORT_SYMBOL(nvm_dev_dma_alloc);

void nvm_dev_dma_free(struct nvm_dev *dev, void *addr, dma_addr_t dma_handler) {
  dev->ops->dev_dma_free(dev->dma_pool, addr, dma_handler);
}
EXPORT_SYMBOL(nvm_dev_dma_free);

static struct nvm_dev *nvm_find_nvm_dev(const char *name) {
  struct nvm_dev *dev;

  list_for_each_entry(dev, &nvm_devices,
                      devices) if (!strcmp(name, dev->name)) return dev;

  return NULL;
}

static int nvm_set_rqd_ppalist(struct nvm_tgt_dev *tgt_dev, struct nvm_rq *rqd,
                               const struct ppa_addr *ppas, int nr_ppas) {
  struct nvm_dev *dev = tgt_dev->parent;
  struct nvm_geo *geo = &tgt_dev->geo;
  int i, plane_cnt, pl_idx;
  struct ppa_addr ppa;

  if (geo->pln_mode == NVM_PLANE_SINGLE && nr_ppas == 1) {
    rqd->nr_ppas = nr_ppas;
    rqd->ppa_addr = ppas[0];

    return 0;
  }

  rqd->nr_ppas = nr_ppas;
  rqd->ppa_list = nvm_dev_dma_alloc(dev, GFP_KERNEL, &rqd->dma_ppa_list);
  if (!rqd->ppa_list) {
    pr_err("nvm: failed to allocate dma memory\n");
    return -ENOMEM;
  }

  plane_cnt = geo->pln_mode;
  rqd->nr_ppas *= plane_cnt;

  for (i = 0; i < nr_ppas; i++) {
    for (pl_idx = 0; pl_idx < plane_cnt; pl_idx++) {
      ppa = ppas[i];
      ppa.g.pl = pl_idx;
      rqd->ppa_list[(pl_idx * nr_ppas) + i] = ppa;
    }
  }

  return 0;
}

static void nvm_free_rqd_ppalist(struct nvm_tgt_dev *tgt_dev,
                                 struct nvm_rq *rqd) {
  if (!rqd->ppa_list)
    return;

  nvm_dev_dma_free(tgt_dev->parent, rqd->ppa_list, rqd->dma_ppa_list);
}

int nvm_get_chunk_meta(struct nvm_tgt_dev *tgt_dev, struct nvm_chk_meta *meta,
                       struct ppa_addr ppa, int nchks) {
  struct nvm_dev *dev = tgt_dev->parent;

  nvm_ppa_tgt_to_dev(tgt_dev, &ppa, 1);

  return dev->ops->get_chk_meta(tgt_dev->parent, meta, (sector_t)ppa.ppa,
                                nchks);
}
EXPORT_SYMBOL(nvm_get_chunk_meta);

int nvm_set_tgt_bb_tbl(struct nvm_tgt_dev *tgt_dev, struct ppa_addr *ppas,
                       int nr_ppas, int type) {
  struct nvm_dev *dev = tgt_dev->parent;
  struct nvm_rq rqd;
  int ret;

  if (nr_ppas > NVM_MAX_VLBA) {
    pr_err("nvm: unable to update all blocks atomically\n");
    return -EINVAL;
  }

  memset(&rqd, 0, sizeof(struct nvm_rq));

  nvm_set_rqd_ppalist(tgt_dev, &rqd, ppas, nr_ppas);
  nvm_rq_tgt_to_dev(tgt_dev, &rqd);

  ret = dev->ops->set_bb_tbl(dev, &rqd.ppa_addr, rqd.nr_ppas, type);
  nvm_free_rqd_ppalist(tgt_dev, &rqd);
  if (ret) {
    pr_err("nvm: failed bb mark\n");
    return -EINVAL;
  }

  return 0;
}
EXPORT_SYMBOL(nvm_set_tgt_bb_tbl);

int nvm_submit_io(struct nvm_tgt_dev *tgt_dev, struct nvm_rq *rqd) {
  struct nvm_dev *dev = tgt_dev->parent;
  int ret;

  if (!dev->ops->submit_io)
    return -ENODEV;

  nvm_rq_tgt_to_dev(tgt_dev, rqd);

  rqd->dev = tgt_dev;

  /* In case of error, fail with right address format */
  ret = dev->ops->submit_io(dev, rqd);
  if (ret)
    nvm_rq_dev_to_tgt(tgt_dev, rqd);
  return ret;
}
EXPORT_SYMBOL(nvm_submit_io);

int nvm_submit_io_sync(struct nvm_tgt_dev *tgt_dev, struct nvm_rq *rqd) {
  struct nvm_dev *dev = tgt_dev->parent;
  int ret;

  if (!dev->ops->submit_io_sync)
    return -ENODEV;

  nvm_rq_tgt_to_dev(tgt_dev, rqd);

  rqd->dev = tgt_dev;

  /* In case of error, fail with right address format */
  ret = dev->ops->submit_io_sync(dev, rqd);
  nvm_rq_dev_to_tgt(tgt_dev, rqd);

  return ret;
}
EXPORT_SYMBOL(nvm_submit_io_sync);

void nvm_end_io(struct nvm_rq *rqd) {
  struct nvm_tgt_dev *tgt_dev = rqd->dev;

  /* Convert address space */
  if (tgt_dev)
    nvm_rq_dev_to_tgt(tgt_dev, rqd);

  if (rqd->end_io)
    rqd->end_io(rqd);
}
EXPORT_SYMBOL(nvm_end_io);

/*
 * folds a bad block list from its plane representation to its virtual
 * block representation. The fold is done in place and reduced size is
 * returned.
 *
 * If any of the planes status are bad or grown bad block, the virtual block
 * is marked bad. If not bad, the first plane state acts as the block state.
 */
int nvm_bb_tbl_fold(struct nvm_dev *dev, u8 *blks, int nr_blks) {
  struct nvm_geo *geo = &dev->geo;
  int blk, offset, pl, blktype;

  if (nr_blks != geo->num_chk * geo->pln_mode)
    return -EINVAL;

  for (blk = 0; blk < geo->num_chk; blk++) {
    offset = blk * geo->pln_mode;
    blktype = blks[offset];

    /* Bad blocks on any planes take precedence over other types */
    for (pl = 0; pl < geo->pln_mode; pl++) {
      if (blks[offset + pl] & (NVM_BLK_T_BAD | NVM_BLK_T_GRWN_BAD)) {
        blktype = blks[offset + pl];
        break;
      }
    }

    blks[blk] = blktype;
  }

  return geo->num_chk;
}
EXPORT_SYMBOL(nvm_bb_tbl_fold);

int nvm_get_tgt_bb_tbl(struct nvm_tgt_dev *tgt_dev, struct ppa_addr ppa,
                       u8 *blks) {
  struct nvm_dev *dev = tgt_dev->parent;

  nvm_ppa_tgt_to_dev(tgt_dev, &ppa, 1);

  return dev->ops->get_bb_tbl(dev, ppa, blks);
}
EXPORT_SYMBOL(nvm_get_tgt_bb_tbl);

static int nvm_core_init(struct nvm_dev *dev) {
  struct nvm_geo *geo = &dev->geo;
  int ret;

  dev->lun_map =
      kcalloc(BITS_TO_LONGS(geo->all_luns), sizeof(unsigned long), GFP_KERNEL);
  if (!dev->lun_map)
    return -ENOMEM;

  INIT_LIST_HEAD(&dev->area_list);
  INIT_LIST_HEAD(&dev->targets);
  mutex_init(&dev->mlock);
  spin_lock_init(&dev->lock);

  ret = nvm_register_map(dev);
  if (ret)
    goto err_fmtype;

  return 0;
err_fmtype:
  kfree(dev->lun_map);
  return ret;
}

static void nvm_free(struct nvm_dev *dev) {
  if (!dev)
    return;

  if (dev->dma_pool)
    dev->ops->destroy_dma_pool(dev->dma_pool);

  nvm_unregister_map(dev);
  kfree(dev->lun_map);
  kfree(dev);
}

static int nvm_init(struct nvm_dev *dev) {
  struct nvm_geo *geo = &dev->geo;
  int ret = -EINVAL;

  if (dev->ops->identity(dev)) {
    pr_err("nvm: device could not be identified\n");
    goto err;
  }

  pr_debug("nvm: ver:%u.%u nvm_vendor:%x\n", geo->major_ver_id,
           geo->minor_ver_id, geo->vmnt);

  ret = nvm_core_init(dev);
  if (ret) {
    pr_err("nvm: could not initialize core structures.\n");
    goto err;
  }

  pr_info("nvm: registered %s [%u/%u/%u/%u/%u]\n", dev->name, dev->geo.ws_min,
          dev->geo.ws_opt, dev->geo.num_chk, dev->geo.all_luns,
          dev->geo.num_ch);
  return 0;
err:
  pr_err("nvm: failed to initialize nvm\n");
  return ret;
}

struct nvm_dev *nvm_alloc_dev(int node) {
  return kzalloc_node(sizeof(struct nvm_dev), GFP_KERNEL, node);
}
EXPORT_SYMBOL(nvm_alloc_dev);

int nvm_register(struct nvm_dev *dev) {
  int ret;

  if (!dev->q || !dev->ops)
    return -EINVAL;

  dev->dma_pool = dev->ops->create_dma_pool(dev, "ppalist");
  if (!dev->dma_pool) {
    pr_err("nvm: could not create dma pool\n");
    return -ENOMEM;
  }

  ret = nvm_init(dev);
  if (ret)
    goto err_init;

  /* register device with a supported media manager */
  down_write(&nvm_lock);
  list_add(&dev->devices, &nvm_devices);
  up_write(&nvm_lock);

  return 0;
err_init:
  dev->ops->destroy_dma_pool(dev->dma_pool);
  return ret;
}
EXPORT_SYMBOL(nvm_register);

void nvm_unregister(struct nvm_dev *dev) {
  struct nvm_target *t, *tmp;

  mutex_lock(&dev->mlock);
  list_for_each_entry_safe(t, tmp, &dev->targets, list) {
    if (t->dev->parent != dev)
      continue;
    __nvm_remove_target(t, false);
  }
  mutex_unlock(&dev->mlock);

  down_write(&nvm_lock);
  list_del(&dev->devices);
  up_write(&nvm_lock);

  nvm_free(dev);
}
EXPORT_SYMBOL(nvm_unregister);

static int __nvm_configure_create(struct nvm_ioctl_create *create) {
  struct nvm_dev *dev;

  down_write(&nvm_lock);
  dev = nvm_find_nvm_dev(create->dev);
  up_write(&nvm_lock);

  if (!dev) {
    pr_err("nvm: device not found\n");
    return -EINVAL;
  }

  return nvm_create_tgt(dev, create);
}

static long nvm_ioctl_info(struct file *file, void __user *arg) {
  struct nvm_ioctl_info *info;
  struct nvm_tgt_type *tt;
  int tgt_iter = 0;

  info = memdup_user(arg, sizeof(struct nvm_ioctl_info));
  if (IS_ERR(info))
    return -EFAULT;

  info->version[0] = NVM_VERSION_MAJOR;
  info->version[1] = NVM_VERSION_MINOR;
  info->version[2] = NVM_VERSION_PATCH;

  down_write(&nvm_tgtt_lock);
  list_for_each_entry(tt, &nvm_tgt_types, list) {
    struct nvm_ioctl_info_tgt *tgt = &info->tgts[tgt_iter];

    tgt->version[0] = tt->version[0];
    tgt->version[1] = tt->version[1];
    tgt->version[2] = tt->version[2];
    strncpy(tgt->tgtname, tt->name, NVM_TTYPE_NAME_MAX);

    tgt_iter++;
  }

  info->tgtsize = tgt_iter;
  up_write(&nvm_tgtt_lock);

  if (copy_to_user(arg, info, sizeof(struct nvm_ioctl_info))) {
    kfree(info);
    return -EFAULT;
  }

  kfree(info);
  return 0;
}

static long nvm_ioctl_get_devices(struct file *file, void __user *arg) {
  struct nvm_ioctl_get_devices *devices;
  struct nvm_dev *dev;
  int i = 0;

  devices = kzalloc(sizeof(struct nvm_ioctl_get_devices), GFP_KERNEL);
  if (!devices)
    return -ENOMEM;

  down_write(&nvm_lock);
  list_for_each_entry(dev, &nvm_devices, devices) {
    struct nvm_ioctl_device_info *info = &devices->info[i];

    strlcpy(info->devname, dev->name, sizeof(info->devname));

    /* kept for compatibility */
    info->bmversion[0] = 1;
    info->bmversion[1] = 0;
    info->bmversion[2] = 0;
    strlcpy(info->bmname, "gennvm", sizeof(info->bmname));
    i++;

    if (i > 31) {
      pr_err("nvm: max 31 devices can be reported.\n");
      break;
    }
  }
  up_write(&nvm_lock);

  devices->nr_devices = i;

  if (copy_to_user(arg, devices, sizeof(struct nvm_ioctl_get_devices))) {
    kfree(devices);
    return -EFAULT;
  }

  kfree(devices);
  return 0;
}

static long nvm_ioctl_dev_create(struct file *file, void __user *arg) {
  struct nvm_ioctl_create create;

  if (copy_from_user(&create, arg, sizeof(struct nvm_ioctl_create)))
    return -EFAULT;

  if (create.conf.type == NVM_CONFIG_TYPE_EXTENDED && create.conf.e.rsv != 0) {
    pr_err("nvm: reserved config field in use\n");
    return -EINVAL;
  }

  create.dev[DISK_NAME_LEN - 1] = '\0';
  create.tgttype[NVM_TTYPE_NAME_MAX - 1] = '\0';
  create.tgtname[DISK_NAME_LEN - 1] = '\0';

  if (create.flags != 0) {
    __u32 flags = create.flags;

    /* Check for valid flags */
    if (flags & NVM_TARGET_FACTORY)
      flags &= ~NVM_TARGET_FACTORY;

    if (flags) {
      pr_err("nvm: flag not supported\n");
      return -EINVAL;
    }
  }

  return __nvm_configure_create(&create);
}

static long nvm_ioctl_dev_remove(struct file *file, void __user *arg) {
  struct nvm_ioctl_remove remove;
  struct nvm_dev *dev;
  int ret = 0;

  if (copy_from_user(&remove, arg, sizeof(struct nvm_ioctl_remove)))
    return -EFAULT;

  remove.tgtname[DISK_NAME_LEN - 1] = '\0';

  if (remove.flags != 0) {
    pr_err("nvm: no flags supported\n");
    return -EINVAL;
  }

  list_for_each_entry(dev, &nvm_devices, devices) {
    ret = nvm_remove_tgt(dev, &remove);
    if (!ret)
      break;
  }

  return ret;
}

/* kept for compatibility reasons */
static long nvm_ioctl_dev_init(struct file *file, void __user *arg) {
  struct nvm_ioctl_dev_init init;

  if (copy_from_user(&init, arg, sizeof(struct nvm_ioctl_dev_init)))
    return -EFAULT;

  if (init.flags != 0) {
    pr_err("nvm: no flags supported\n");
    return -EINVAL;
  }

  return 0;
}

/* Kept for compatibility reasons */
static long nvm_ioctl_dev_factory(struct file *file, void __user *arg) {
  struct nvm_ioctl_dev_factory fact;

  if (copy_from_user(&fact, arg, sizeof(struct nvm_ioctl_dev_factory)))
    return -EFAULT;

  fact.dev[DISK_NAME_LEN - 1] = '\0';

  if (fact.flags & ~(NVM_FACTORY_NR_BITS - 1))
    return -EINVAL;

  return 0;
}

static long nvm_ctl_ioctl(struct file *file, uint cmd, unsigned long arg) {
  void __user *argp = (void __user *)arg;

  if (!capable(CAP_SYS_ADMIN))
    return -EPERM;

  switch (cmd) {
  case NVM_INFO:
    return nvm_ioctl_info(file, argp);
  case NVM_GET_DEVICES:
    return nvm_ioctl_get_devices(file, argp);
  case NVM_DEV_CREATE:
    return nvm_ioctl_dev_create(file, argp);
  case NVM_DEV_REMOVE:
    return nvm_ioctl_dev_remove(file, argp);
  case NVM_DEV_INIT:
    return nvm_ioctl_dev_init(file, argp);
  case NVM_DEV_FACTORY:
    return nvm_ioctl_dev_factory(file, argp);
  }
  return 0;
}

static const struct file_operations _ctl_fops = {
    .open = nonseekable_open,
    .unlocked_ioctl = nvm_ctl_ioctl,
    .owner = THIS_MODULE,
    .llseek = noop_llseek,
};

static struct miscdevice _nvm_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "lightnvm",
    .nodename = "lightnvm/control",
    .fops = &_ctl_fops,
};
builtin_misc_device(_nvm_misc);
