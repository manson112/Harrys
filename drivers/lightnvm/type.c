
/* common format */
#define NVM_GEN_CH_BITS (8)
#define NVM_GEN_LUN_BITS (8)
#define NVM_GEN_BLK_BITS (16)
#define NVM_GEN_RESERVED (32)

/* 1.2 format */
#define NVM_12_PG_BITS (16)
#define NVM_12_PL_BITS (4)
#define NVM_12_SEC_BITS (4)
#define NVM_12_RESERVED (8)

/* 2.0 format */
#define NVM_20_SEC_BITS (24)
#define NVM_20_RESERVED (8)

struct nvme_ns {
  struct list_head list;

  struct nvme_ctrl *ctrl;
  struct request_queue *queue;
  struct gendisk *disk;
  struct list_head siblings;
  struct nvm_dev *ndev;
  struct kref kref;
  struct nvme_ns_head *head;

  int lba_shift;
  u16 ms;
  u16 sgs;
  u32 sws;
  bool ext;
  u8 pi_type;
  unsigned long flags;
#define NVME_NS_REMOVING 0
#define NVME_NS_DEAD 1
  u16 noiob;

#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS
  struct nvme_fault_inject fault_inject;
#endif
};

struct list_head {
  struct list_head *next, *prev;
};

typedef int(nvm_id_fn)(struct nvm_dev *);
typedef int(nvm_op_bb_tbl_fn)(struct nvm_dev *, struct ppa_addr, u8 *);
typedef int(nvm_op_set_bb_fn)(struct nvm_dev *, struct ppa_addr *, int, int);
typedef int(nvm_get_chk_meta_fn)(struct nvm_dev *, struct nvm_chk_meta *,
                                 sector_t, int);
typedef int(nvm_submit_io_fn)(struct nvm_dev *, struct nvm_rq *);
typedef int(nvm_submit_io_sync_fn)(struct nvm_dev *, struct nvm_rq *);
typedef void *(nvm_create_dma_pool_fn)(struct nvm_dev *, char *);
typedef void(nvm_destroy_dma_pool_fn)(void *);
typedef void *(nvm_dev_dma_alloc_fn)(struct nvm_dev *, void *, gfp_t,
                                     dma_addr_t *);
typedef void(nvm_dev_dma_free_fn)(void *, void *, dma_addr_t);

struct nvm_dev_ops {
  nvm_id_fn *identity;
  nvm_op_bb_tbl_fn *get_bb_tbl;
  nvm_op_set_bb_fn *set_bb_tbl;

  nvm_get_chk_meta_fn *get_chk_meta;

  nvm_submit_io_fn *submit_io;
  nvm_submit_io_sync_fn *submit_io_sync;

  nvm_create_dma_pool_fn *create_dma_pool;
  nvm_destroy_dma_pool_fn *destroy_dma_pool;
  nvm_dev_dma_alloc_fn *dev_dma_alloc;
  nvm_dev_dma_free_fn *dev_dma_free;
};
/* Instance geometry */
struct nvm_geo {
  /* device reported version */
  u8 major_ver_id;
  u8 minor_ver_id;

  /* kernel short version */
  u8 version;

  /* instance specific geometry */
  int num_ch;                    //채널 수
  int num_lun; /* per channel */ //채널 당 lun 수

  /* calculated values */
  int all_luns; /* across channels */   //모든 lun 수 (lun * 채널 수)
  int all_chunks; /* across channels */ //모든 chunk 수

  // over-provision
  // 논리적인 블록보다 물리적인 블록의 수가 더 많도록 해주는 것인데,
  //일정 비율의 물리 블록을 SSD 컨트롤러는 볼 수 있지만 운영 체제나
  //파일 시스템은 보지 못하도록 예약해두는 것이다.
  int op; /* over-provision in instance */

  //채널에 속하는 총 sector 수 ??
  sector_t total_secs; /* across channels */
  /* chunk geometry */

  u32 num_chk; // lun 당 chunk 수

  u32 clba; // chunk 당 sector 수

  u16 csecs; // sector 크기

  //??
  u16 sos; /* out-of-band area size */

  /* device write constrains */
  //최소 쓰기 사이즈
  u32 ws_min; /* minimum write size */

  u32 ws_opt;    //최적 쓰기 사이즈
                 //??
  u32 mw_cunits; /* distance required for successful read */

  u32 maxoc; //최대 open chunk 수

  u32 maxocpu; // pu 당 최대 open chunk 수

  /* device capabilities */
  //디바이스 용량
  u32 mccap;

  /* device timings */
  //평균, 최대 읽기 시간
  u32 trdt; /* Avg. Tread (ns) */
  u32 trdm; /* Max Tread (ns) */
            //평균, 최대 쓰기 시간
  u32 tprt; /* Avg. Tprog (ns) */
  u32 tprm; /* Max Tprog (ns) */
            //평균, 최대 지우기 시간
  u32 tbet; /* Avg. Terase (ns) */
  u32 tbem; /* Max Terase (ns) */

  /* generic address format */
  //주소 형식
  struct nvm_addrf addrf;

  /* 1.2 compatibility */
  // 1.2 버전 호환성
  u8 vmnt;
  u32 cap;
  u32 dom;

  u8 mtype;
  u8 fmtype;

  u16 cpar;
  u32 mpos;

  u8 num_pln;
  u8 pln_mode;
  u16 num_pg;
  u16 fpg_sz;
};

/* sub-device structure */
struct nvm_tgt_dev {
  /* Device information */
  struct nvm_geo geo;

  /* Base ppas for target LUNs */
  struct ppa_addr *luns;

  struct request_queue *q;

  struct nvm_dev *parent;
  void *map;
};

struct nvm_dev {
  struct nvm_dev_ops *ops;

  struct list_head devices;

  /* Device information */
  struct nvm_geo geo;

  unsigned long *lun_map;
  void *dma_pool;

  /* Backend device */
  struct request_queue *q;
  char name[DISK_NAME_LEN];
  void *private_data;

  void *rmap;

  struct mutex mlock;
  spinlock_t lock;

  /* target management */
  struct list_head area_list;
  struct list_head targets;
};

struct nvm_target {
  struct list_head list;
  struct nvm_tgt_dev *dev;
  struct nvm_tgt_type *type;
  struct gendisk *disk;
};

struct nvm_tgt_type {
  const char *name;
  unsigned int version[3];

  /* target entry points */
  nvm_tgt_make_rq_fn *make_rq;
  nvm_tgt_capacity_fn *capacity;

  /* module-specific init/teardown */
  nvm_tgt_init_fn *init;
  nvm_tgt_exit_fn *exit;

  /* sysfs */
  nvm_tgt_sysfs_init_fn *sysfs_init;
  nvm_tgt_sysfs_exit_fn *sysfs_exit;

  /* For internal use */
  struct list_head list;
  struct module *owner;
};

struct request_queue {
  /*
   * Together with queue_head for cacheline sharing
   */
  struct list_head queue_head;
  struct request *last_merge;
  struct elevator_queue *elevator;
  int nr_rqs[2];      /* # allocated [a]sync rqs */
  int nr_rqs_elvpriv; /* # allocated rqs w/ elvpriv */

  atomic_t shared_hctx_restart;

  struct blk_queue_stats *stats;
  struct rq_wb *rq_wb;

  /*
   * If blkcg is not used, @q->root_rl serves all requests.  If blkcg
   * is used, root blkg allocates from @q->root_rl and all other
   * blkgs from their own blkg->rl.  Which one to use should be
   * determined using bio_request_list().
   */
  struct request_list root_rl;

  request_fn_proc *request_fn;
  make_request_fn *make_request_fn;
  poll_q_fn *poll_fn;
  prep_rq_fn *prep_rq_fn;
  unprep_rq_fn *unprep_rq_fn;
  softirq_done_fn *softirq_done_fn;
  rq_timed_out_fn *rq_timed_out_fn;
  dma_drain_needed_fn *dma_drain_needed;
  lld_busy_fn *lld_busy_fn;
  /* Called just after a request is allocated */
  init_rq_fn *init_rq_fn;
  /* Called just before a request is freed */
  exit_rq_fn *exit_rq_fn;
  /* Called from inside blk_get_request() */
  void (*initialize_rq_fn)(struct request *rq);

  const struct blk_mq_ops *mq_ops;

  unsigned int *mq_map;

  /* sw queues */
  struct blk_mq_ctx __percpu *queue_ctx;
  unsigned int nr_queues;

  unsigned int queue_depth;

  /* hw dispatch queues */
  struct blk_mq_hw_ctx **queue_hw_ctx;
  unsigned int nr_hw_queues;

  /*
   * Dispatch queue sorting
   */
  sector_t end_sector;
  struct request *boundary_rq;

  /*
   * Delayed queue handling
   */
  struct delayed_work delay_work;

  struct backing_dev_info *backing_dev_info;

  /*
   * The queue owner gets to use this for whatever they like.
   * ll_rw_blk doesn't touch it.
   */
  void *queuedata;

  /*
   * various queue flags, see QUEUE_* below
   */
  unsigned long queue_flags;

  /*
   * ida allocated id for this queue.  Used to index queues from
   * ioctx.
   */
  int id;

  /*
   * queue needs bounce pages for pages above this limit
   */
  gfp_t bounce_gfp;

  /*
   * protects queue structures from reentrancy. ->__queue_lock should
   * _never_ be used directly, it is queue private. always use
   * ->queue_lock.
   */
  spinlock_t __queue_lock;
  spinlock_t *queue_lock;

  /*
   * queue kobject
   */
  struct kobject kobj;

  /*
   * mq queue kobject
   */
  struct kobject mq_kobj;

#ifdef CONFIG_BLK_DEV_INTEGRITY
  struct blk_integrity integrity;
#endif /* CONFIG_BLK_DEV_INTEGRITY */

#ifdef CONFIG_PM
  struct device *dev;
  int rpm_status;
  unsigned int nr_pending;
#endif

  /*
   * queue settings
   */
  unsigned long nr_requests; /* Max # of requests */
  unsigned int nr_congestion_on;
  unsigned int nr_congestion_off;
  unsigned int nr_batching;

  unsigned int dma_drain_size;
  void *dma_drain_buffer;
  unsigned int dma_pad_mask;
  unsigned int dma_alignment;

  struct blk_queue_tag *queue_tags;
  struct list_head tag_busy_list;

  unsigned int nr_sorted;
  unsigned int in_flight[2];

  /*
   * Number of active block driver functions for which blk_drain_queue()
   * must wait. Must be incremented around functions that unlock the
   * queue_lock internally, e.g. scsi_request_fn().
   */
  unsigned int request_fn_active;

  unsigned int rq_timeout;
  int poll_nsec;

  struct blk_stat_callback *poll_cb;
  struct blk_rq_stat poll_stat[BLK_MQ_POLL_STATS_BKTS];

  struct timer_list timeout;
  struct work_struct timeout_work;
  struct list_head timeout_list;

  struct list_head icq_list;
#ifdef CONFIG_BLK_CGROUP
  DECLARE_BITMAP(blkcg_pols, BLKCG_MAX_POLS);
  struct blkcg_gq *root_blkg;
  struct list_head blkg_list;
#endif

  struct queue_limits limits;

  /*
   * Zoned block device information for request dispatch control.
   * nr_zones is the total number of zones of the device. This is always
   * 0 for regular block devices. seq_zones_bitmap is a bitmap of nr_zones
   * bits which indicates if a zone is conventional (bit clear) or
   * sequential (bit set). seq_zones_wlock is a bitmap of nr_zones
   * bits which indicates if a zone is write locked, that is, if a write
   * request targeting the zone was dispatched. All three fields are
   * initialized by the low level device driver (e.g. scsi/sd.c).
   * Stacking drivers (device mappers) may or may not initialize
   * these fields.
   */
  unsigned int nr_zones;
  unsigned long *seq_zones_bitmap;
  unsigned long *seq_zones_wlock;

  /*
   * sg stuff
   */
  unsigned int sg_timeout;
  unsigned int sg_reserved_size;
  int node;
#ifdef CONFIG_BLK_DEV_IO_TRACE
  struct blk_trace *blk_trace;
  struct mutex blk_trace_mutex;
#endif
  /*
   * for flush operations
   */
  struct blk_flush_queue *fq;

  struct list_head requeue_list;
  spinlock_t requeue_lock;
  struct delayed_work requeue_work;

  struct mutex sysfs_lock;

  int bypass_depth;
  atomic_t mq_freeze_depth;

#if defined(CONFIG_BLK_DEV_BSG)
  bsg_job_fn *bsg_job_fn;
  struct bsg_class_device bsg_dev;
#endif

#ifdef CONFIG_BLK_DEV_THROTTLING
  /* Throttle data */
  struct throtl_data *td;
#endif
  struct rcu_head rcu_head;
  wait_queue_head_t mq_freeze_wq;
  struct percpu_ref q_usage_counter;
  struct list_head all_q_node;

  struct blk_mq_tag_set *tag_set;
  struct list_head tag_set_list;
  struct bio_set *bio_split;

#ifdef CONFIG_BLK_DEBUG_FS
  struct dentry *debugfs_dir;
  struct dentry *sched_debugfs_dir;
#endif

  bool mq_sysfs_init_done;

  size_t cmd_size;
  void *rq_alloc_data;

  struct work_struct release_work;

#define BLK_MAX_WRITE_HINTS 5
  u64 write_hints[BLK_MAX_WRITE_HINTS];
};
struct nvm_addrf {
  u8 ch_len;
  u8 lun_len;
  u8 chk_len;
  u8 sec_len;
  u8 rsv_len[2];

  u8 ch_offset;
  u8 lun_offset;
  u8 chk_offset;
  u8 sec_offset;
  u8 rsv_off[2];

  u64 ch_mask;
  u64 lun_mask;
  u64 chk_mask;
  u64 sec_mask;
  u64 rsv_mask[2];
};

struct ppa_addr {
  /* Generic structure for all addresses */
  union {
    /* generic device format */
    struct {
      u64 ch : NVM_GEN_CH_BITS;
      u64 lun : NVM_GEN_LUN_BITS;
      u64 blk : NVM_GEN_BLK_BITS;
      u64 reserved : NVM_GEN_RESERVED;
    } a;

    /* 1.2 device format */
    struct {
      u64 ch : NVM_GEN_CH_BITS;
      u64 lun : NVM_GEN_LUN_BITS;
      u64 blk : NVM_GEN_BLK_BITS;
      u64 pg : NVM_12_PG_BITS;
      u64 pl : NVM_12_PL_BITS;
      u64 sec : NVM_12_SEC_BITS;
      u64 reserved : NVM_12_RESERVED;
    } g;

    /* 2.0 device format */
    struct {
      u64 grp : NVM_GEN_CH_BITS;
      u64 pu : NVM_GEN_LUN_BITS;
      u64 chk : NVM_GEN_BLK_BITS;
      u64 sec : NVM_20_SEC_BITS;
      u64 reserved : NVM_20_RESERVED;
    } m;

    struct {
      u64 line : 63;
      u64 is_cached : 1;
    } c;

    u64 ppa;
  };
};
