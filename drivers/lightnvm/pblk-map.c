/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
 *                  Matias Bjorling <matias@cnexlabs.com>
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
 * pblk-map.c - pblk's lba-ppa mapping strategy
 *
 */

#include "pblk.h"

static int pblk_map_page_data(struct pblk *pblk, unsigned int sentry,
                              struct ppa_addr *ppa_list,
                              unsigned long *lun_bitmap,
                              struct pblk_sec_meta *meta_list,
                              unsigned int valid_secs) {
  // line //pblk_line_get_data
  struct pblk_line *line = pblk_line_get_data(pblk);
  // end metadata
  struct pblk_emeta *emeta;
  // write context
  struct pblk_w_ctx *w_ctx;
  // lba 리스트(littel endian)
  __le64 *lba_list;
  //물리 주소
  u64 paddr;

  //컨트롤러가 필요한 최소 page 양
  int nr_secs = pblk->min_write_pgs;
  int i;

  // line이 가득 찼을 경우
  // = map 할 sector가 없을 경우
  if (pblk_line_is_full(line)) {
    struct pblk_line *prev_line = line;

    /* If we cannot allocate a new line, make sure to store metadata
     * on current line and then fail
     */
    //기존의 line을 닫고 다음 line에 meta data를 설정한다.
    line = pblk_line_replace_data(pblk);
    //기존 line의 end metadata를 설정
    pblk_line_close_meta(pblk, prev_line);

    if (!line)
      return -EINTR;
  }

  emeta = line->emeta;
  // end metadata 에서 lba list를 가져온다.
  lba_list = emeta_to_lbas(pblk, emeta->buf);

  // line에 해당하는 물리 주소를 가져온다. //pblk_alloc_page
  paddr = pblk_alloc_page(pblk, line, nr_secs);

  for (i = 0; i < nr_secs; i++, paddr++) {
    __le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

    /* ppa to be sent to the device */
    // u64 ppadr을 ppa_addr 구조체로 변환
    ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);

    /* Write context for target bio completion on write buffer. Note
     * that the write buffer is protected by the sync backpointer,
     * and a single writer thread have access to each specific entry
     * at a time. Thus, it is safe to modify the context for the
     * entry we are setting up for submission without taking any
     * lock or memory barrier.
     */
    //유효한 sector 수 만큼
    if (i < valid_secs) {
      kref_get(&line->ref);
      // pblk의 ring write buffer의 position(sentry+i)에 해당하는 write context
      // 반환
      w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
      // write context 의 ppa를 ppa_list의 i번째 ppa 선택
      w_ctx->ppa = ppa_list[i];
      // write context 의 lba를 little endian 으로 바꿔 meta_list[i].lba에 저장
      meta_list[i].lba = cpu_to_le64(w_ctx->lba);
      // lba_list[paddr]에도 같이
      lba_list[paddr] = cpu_to_le64(w_ctx->lba);

      if (lba_list[paddr] != addr_empty)
        /* Number of valid lbas mapped in line */
        line->nr_valid_lbas++;
      else
        atomic64_inc(&pblk->pad_wa);
    } else {
      lba_list[paddr] = meta_list[i].lba = addr_empty;
      __pblk_map_invalidate(pblk, line, paddr);
    }
  }

  pblk_down_rq(pblk, ppa_list, nr_secs, lun_bitmap);
  return 0;
}

void pblk_map_rq(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
                 unsigned long *lun_bitmap, unsigned int valid_secs,
                 unsigned int off) {
  struct pblk_sec_meta *meta_list = rqd->meta_list;
  unsigned int map_secs;
  int min = pblk->min_write_pgs;
  int i;

  for (i = off; i < rqd->nr_ppas; i += min) {
    map_secs = (i + min > valid_secs) ? (valid_secs % min) : m in;
    // pblk_map_page_data가 정상적으로 작동하지 않았을 때
    if (pblk_map_page_data(pblk, sentry + i, &rqd->ppa_list[i], lun_bitmap,
                           &meta_list[i], map_secs)) {
      bio_put(rqd->bio);
      pblk_free_rqd(pblk, rqd, PBLK_WRITE);
      pblk_pipeline_stop(pblk);
    }
  }
}

/* only if erase_ppa is set, acquire erase semaphore */
void pblk_map_erase_rq(struct pblk *pblk, struct nvm_rq *rqd,
                       unsigned int sentry, unsigned long *lun_bitmap,
                       unsigned int valid_secs, struct ppa_addr *erase_ppa) {
  struct nvm_tgt_dev *dev = pblk->dev;
  struct nvm_geo *geo = &dev->geo;
  struct pblk_line_meta *lm = &pblk->lm;
  struct pblk_sec_meta *meta_list = rqd->meta_list;
  struct pblk_line *e_line, *d_line;
  unsigned int map_secs;
  int min = pblk->min_write_pgs;
  int i, erase_lun;

  for (i = 0; i < rqd->nr_ppas; i += min) {
    map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
    if (pblk_map_page_data(pblk, sentry + i, &rqd->ppa_list[i], lun_bitmap,
                           &meta_list[i], map_secs)) {
      bio_put(rqd->bio);
      pblk_free_rqd(pblk, rqd, PBLK_WRITE);
      pblk_pipeline_stop(pblk);
    }

    erase_lun = pblk_ppa_to_pos(geo, rqd->ppa_list[i]);

    /* line can change after page map. We might also be writing the
     * last line.
     */
    e_line = pblk_line_get_erase(pblk);
    if (!e_line)
      return pblk_map_rq(pblk, rqd, sentry, lun_bitmap, valid_secs, i + min);

    spin_lock(&e_line->lock);
    if (!test_bit(erase_lun, e_line->erase_bitmap)) {
      set_bit(erase_lun, e_line->erase_bitmap);
      atomic_dec(&e_line->left_eblks);

      *erase_ppa = rqd->ppa_list[i];
      erase_ppa->a.blk = e_line->id;

      spin_unlock(&e_line->lock);

      /* Avoid evaluating e_line->left_eblks */
      return pblk_map_rq(pblk, rqd, sentry, lun_bitmap, valid_secs, i + min);
    }
    spin_unlock(&e_line->lock);
  }

  d_line = pblk_line_get_data(pblk);

  /* line can change after page map. We might also be writing the
   * last line.
   */
  e_line = pblk_line_get_erase(pblk);
  if (!e_line)
    return;

  /* Erase blocks that are bad in this line but might not be in next */
  if (unlikely(pblk_ppa_empty(*erase_ppa)) &&
      bitmap_weight(d_line->blk_bitmap, lm->blk_per_line)) {
    int bit = -1;

  retry:
    bit = find_next_bit(d_line->blk_bitmap, lm->blk_per_line, bit + 1);
    if (bit >= lm->blk_per_line)
      return;

    spin_lock(&e_line->lock);
    if (test_bit(bit, e_line->erase_bitmap)) {
      spin_unlock(&e_line->lock);
      goto retry;
    }
    spin_unlock(&e_line->lock);

    set_bit(bit, e_line->erase_bitmap);
    atomic_dec(&e_line->left_eblks);
    *erase_ppa = pblk->luns[bit].bppa; /* set ch and lun */
    erase_ppa->a.blk = e_line->id;
  }
}
