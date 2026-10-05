# DNS 区域变更影响分析 API

基于 **Python + FastAPI + dnspython** 的离线 DNS 区域（zone）变更影响分析服务。
输入同一域名的两版 BIND 区域文本（基线 / 候选），在**不发起任何网络查询**的前提下，
按 **响应码 + RRset + 终止原因** 比较域内所有名称、所有受支持类型的应答，
输出**互斥且完备**的变更模式（pattern）：模式内的查询必然变化，模式外的查询必然不变。

## 功能特性

- `POST /impact`：比较两版区域，返回变更模式列表。每个模式附带见证名（witness）与两版完整应答。
- `POST /resolve`：核对任意（域内）名称 / 类型在两版区域下的应答。
- 仅支持 `SOA`、`NS`、`A`、`AAAA`、`CNAME`、`DNAME` 记录与 `$ORIGIN` / `$TTL` 指令；
  非法文本、越区（out-of-zone）属主名、外部引用（NS/CNAME/DNAME 的 rdata 指向域外）均**整单报错**（HTTP 400）。
- 完整解析语义：委派（delegation/referral）、空非终结点 NODATA（ENT）、最近祖先通配符合成、
  CNAME/DNAME 逐跳重写（DNAME 合成 CNAME）、别名环检测。
- **DNAME 目标子树传播**：DNAME 目标子树中的变化会被映射回 DNAME 子树，
  覆盖两版区域中都**未列出**的名称（见下文原理）。
- 域外不联网：越区查询直接报错，委派只返回 referral，不做递归；别名环仅标记对应模式。

## 快速开始

### Docker Compose 一键启动

```bash
docker compose up --build
```

服务监听 `http://localhost:8000`（交互式文档：`http://localhost:8000/docs`）。

### 本地开发启动

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 运行测试

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

## API

### `POST /impact`

请求体：

```json
{
  "origin": "example.com",
  "baseline": "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ...",
  "candidate": "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ..."
}
```

响应体（字段说明）：

| 字段 | 含义 |
| --- | --- |
| `changed` | 两版区域是否存在任何应答差异 |
| `pattern_count` / `patterns` | 变更模式数量与列表（为空表示两版应答完全一致） |
| `patterns[].match` | 名称模式：精确名、`*.基名`（恰好一层标签）、`**.基名`（零层或多层标签）。属主名中字面的 `*` 标签转义为 `\*` |
| `patterns[].exclude` | 从 `match` 中排除的名称列表（精确名或 `**.` 子树） |
| `patterns[].types` | 该模式覆盖的查询类型（同一模式内所有 名称×类型 组合的应答都发生同样的变化） |
| `patterns[].baseline/candidate` | 该模式在两版区域下的 `rcode` 与 `termination` |
| `patterns[].witness` | 见证：一个具体的名称与类型及其两版完整应答（`answers` 为应答记录链，`authority` 为委派 referral 的 NS 记录） |

**互斥完备保证**：任意（域内名称 × 受支持类型）的查询，若两版应答不同，则恰好被一个模式覆盖；
若相同，则不被任何模式覆盖。该性质由 `tests/test_impact.py` 与 `tests/test_fuzz.py`
中的性质测试（含随机区域对模糊测试）验证。

### `POST /resolve`

请求体在 `/impact` 的基础上增加：

```json
{ "name": "x.d.example.com", "type": "A" }
```

- `name`：绝对名称（末尾点可省略），`@` 表示区域顶点；越区名称返回 400（域外不联网）。
- `type`：`A`、`AAAA`、`CNAME`、`DNAME`、`NS`、`SOA` 之一（大小写不敏感）。

响应体：`baseline` / `candidate` 为两版应答，`changed` 表示二者是否不同。

### 应答对象与终止原因

```json
{ "rcode": "NOERROR", "termination": "exact", "answers": ["..."], "authority": ["..."] }
```

| `termination` | 含义 |
| --- | --- |
| `exact` | 名称精确命中且有所查类型（含 CNAME/DNAME 链的最终落点） |
| `nodata` | 名称存在且有其他类型数据，但无所查类型（NODATA） |
| `nodata-ent` | 空非终结点（empty non-terminal）NODATA |
| `wildcard` | 经最近祖先通配符合成应答 |
| `nodata-wildcard` | 命中通配符但通配符无所查类型 |
| `nxdomain` | 名称不存在 |
| `delegation` | 委派（referral），NS 记录在 `authority` 中 |
| `alias-loop` | CNAME/DNAME 别名环（含超过 32 跳的链） |

`rcode` 为 `NOERROR` 或 `NXDOMAIN`（CNAME/DNAME 链末端为 NXDOMAIN 时整体为 NXDOMAIN）。
比较应答时比较 `rcode`、`termination`、`answers`、`authority` 四者（记录文本含 TTL，名称统一小写）。

## 真实请求与响应示例

示例区域文件见 [`examples/baseline.zone`](examples/baseline.zone) 与
[`examples/candidate.zone`](examples/candidate.zone)：候选版把 `www` 的 A 记录改为
`192.0.2.99`、SOA 序列号 +1、新增 `blog` 的 A 记录、并在 DNAME `d → target` 的目标子树中
新增 `x.target` 的 A 记录。

### 1. `POST /impact`

请求（用 `jq` 把区域文件构造为 JSON；也可直接粘贴 JSON 字符串）：

```bash
jq -n --arg origin example.com \
      --rawfile baseline examples/baseline.zone \
      --rawfile candidate examples/candidate.zone \
      '{origin:$origin, baseline:$baseline, candidate:$candidate}' \
| curl -s http://localhost:8000/impact -H 'Content-Type: application/json' -d @-
```

实际响应（HTTP 200；模式 6、7 即 DNAME 目标子树传播对未列名 `x.d` 的覆盖）：

<details><summary>展开完整响应（9 个模式）</summary>

```json
{
  "origin": "example.com.",
  "changed": true,
  "pattern_count": 9,
  "patterns": [
    {
      "id": 1,
      "match": "api.example.com.",
      "exclude": [],
      "types": ["A"],
      "baseline": {"rcode": "NOERROR", "termination": "exact"},
      "candidate": {"rcode": "NOERROR", "termination": "exact"},
      "witness": {
        "name": "api.example.com.",
        "type": "A",
        "baseline": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": [
            "api.example.com. 300 IN CNAME www.example.com.",
            "www.example.com. 300 IN A 192.0.2.10"
          ],
          "authority": []
        },
        "candidate": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": [
            "api.example.com. 300 IN CNAME www.example.com.",
            "www.example.com. 300 IN A 192.0.2.99"
          ],
          "authority": []
        }
      }
    },
    {
      "id": 2,
      "match": "blog.example.com.",
      "exclude": [],
      "types": ["A"],
      "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain"},
      "candidate": {"rcode": "NOERROR", "termination": "exact"},
      "witness": {
        "name": "blog.example.com.",
        "type": "A",
        "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain", "answers": [], "authority": []},
        "candidate": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": ["blog.example.com. 300 IN A 192.0.2.50"],
          "authority": []
        }
      }
    },
    {
      "id": 3,
      "match": "blog.example.com.",
      "exclude": [],
      "types": ["AAAA", "CNAME", "DNAME", "NS", "SOA"],
      "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain"},
      "candidate": {"rcode": "NOERROR", "termination": "nodata"},
      "witness": {
        "name": "blog.example.com.",
        "type": "AAAA",
        "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain", "answers": [], "authority": []},
        "candidate": {"rcode": "NOERROR", "termination": "nodata", "answers": [], "authority": []}
      }
    },
    {
      "id": 4,
      "match": "example.com.",
      "exclude": [],
      "types": ["SOA"],
      "baseline": {"rcode": "NOERROR", "termination": "exact"},
      "candidate": {"rcode": "NOERROR", "termination": "exact"},
      "witness": {
        "name": "example.com.",
        "type": "SOA",
        "baseline": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": ["example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300"],
          "authority": []
        },
        "candidate": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": ["example.com. 300 IN SOA ns1.example.com. admin.example.com. 2024010102 7200 3600 1209600 300"],
          "authority": []
        }
      }
    },
    {
      "id": 5,
      "match": "www.example.com.",
      "exclude": [],
      "types": ["A"],
      "baseline": {"rcode": "NOERROR", "termination": "exact"},
      "candidate": {"rcode": "NOERROR", "termination": "exact"},
      "witness": {
        "name": "www.example.com.",
        "type": "A",
        "baseline": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": ["www.example.com. 300 IN A 192.0.2.10"],
          "authority": []
        },
        "candidate": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": ["www.example.com. 300 IN A 192.0.2.99"],
          "authority": []
        }
      }
    },
    {
      "id": 6,
      "match": "x.d.example.com.",
      "exclude": [],
      "types": ["A"],
      "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain"},
      "candidate": {"rcode": "NOERROR", "termination": "exact"},
      "witness": {
        "name": "x.d.example.com.",
        "type": "A",
        "baseline": {
          "rcode": "NXDOMAIN", "termination": "nxdomain",
          "answers": [
            "d.example.com. 300 IN DNAME target.example.com.",
            "x.d.example.com. 300 IN CNAME x.target.example.com."
          ],
          "authority": []
        },
        "candidate": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": [
            "d.example.com. 300 IN DNAME target.example.com.",
            "x.d.example.com. 300 IN CNAME x.target.example.com.",
            "x.target.example.com. 300 IN A 192.0.2.31"
          ],
          "authority": []
        }
      }
    },
    {
      "id": 7,
      "match": "x.d.example.com.",
      "exclude": [],
      "types": ["AAAA", "CNAME", "DNAME", "NS", "SOA"],
      "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain"},
      "candidate": {"rcode": "NOERROR", "termination": "nodata"},
      "witness": {
        "name": "x.d.example.com.",
        "type": "AAAA",
        "baseline": {
          "rcode": "NXDOMAIN", "termination": "nxdomain",
          "answers": [
            "d.example.com. 300 IN DNAME target.example.com.",
            "x.d.example.com. 300 IN CNAME x.target.example.com."
          ],
          "authority": []
        },
        "candidate": {
          "rcode": "NOERROR", "termination": "nodata",
          "answers": [
            "d.example.com. 300 IN DNAME target.example.com.",
            "x.d.example.com. 300 IN CNAME x.target.example.com."
          ],
          "authority": []
        }
      }
    },
    {
      "id": 8,
      "match": "x.target.example.com.",
      "exclude": [],
      "types": ["A"],
      "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain"},
      "candidate": {"rcode": "NOERROR", "termination": "exact"},
      "witness": {
        "name": "x.target.example.com.",
        "type": "A",
        "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain", "answers": [], "authority": []},
        "candidate": {
          "rcode": "NOERROR", "termination": "exact",
          "answers": ["x.target.example.com. 300 IN A 192.0.2.31"],
          "authority": []
        }
      }
    },
    {
      "id": 9,
      "match": "x.target.example.com.",
      "exclude": [],
      "types": ["AAAA", "CNAME", "DNAME", "NS", "SOA"],
      "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain"},
      "candidate": {"rcode": "NOERROR", "termination": "nodata"},
      "witness": {
        "name": "x.target.example.com.",
        "type": "AAAA",
        "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain", "answers": [], "authority": []},
        "candidate": {"rcode": "NOERROR", "termination": "nodata", "answers": [], "authority": []}
      }
    }
  ]
}
```

</details>

### 2. `POST /resolve`（DNAME 逐跳重写 + 合成 CNAME）

```bash
curl -s http://localhost:8000/resolve -H 'Content-Type: application/json' -d '{
  "origin": "example.com",
  "baseline": "<baseline.zone 内容>",
  "candidate": "<candidate.zone 内容>",
  "name": "x.d.example.com",
  "type": "A"
}'
```

实际响应（HTTP 200）：

```json
{
  "name": "x.d.example.com.",
  "type": "A",
  "changed": true,
  "baseline": {
    "rcode": "NXDOMAIN",
    "termination": "nxdomain",
    "answers": [
      "d.example.com. 300 IN DNAME target.example.com.",
      "x.d.example.com. 300 IN CNAME x.target.example.com."
    ],
    "authority": []
  },
  "candidate": {
    "rcode": "NOERROR",
    "termination": "exact",
    "answers": [
      "d.example.com. 300 IN DNAME target.example.com.",
      "x.d.example.com. 300 IN CNAME x.target.example.com.",
      "x.target.example.com. 300 IN A 192.0.2.31"
    ],
    "authority": []
  }
}
```

### 3. `POST /resolve`（委派，两版一致）

`name=host.sub.example.com`、`type=AAAA` 的实际响应（HTTP 200）：

```json
{
  "name": "host.sub.example.com.",
  "type": "AAAA",
  "changed": false,
  "baseline": {
    "rcode": "NOERROR",
    "termination": "delegation",
    "answers": [],
    "authority": ["sub.example.com. 300 IN NS ns1.example.com."]
  },
  "candidate": {
    "rcode": "NOERROR",
    "termination": "delegation",
    "answers": [],
    "authority": ["sub.example.com. 300 IN NS ns1.example.com."]
  }
}
```

### 4. 错误示例（整单报错）

候选区域含外部引用 `ext IN CNAME www.other.net.` 时，`POST /impact` 返回 HTTP 400：

```json
{ "detail": "external reference www.other.net. in CNAME record at ext.example.com." }
```

`/resolve` 查询越区名称 `www.other.net` 返回 HTTP 400：

```json
{ "detail": "query name www.other.net. is outside the zone (no out-of-zone resolution is performed)" }
```

### 5. 通配符与 `**` 模式（含排除子树）

基线区域仅含 `wild IN A 192.0.2.5`，候选区域新增 `*.wild IN A 192.0.2.60`。
`POST /impact` 实际响应中的第 3 个模式（共 4 个）：

```json
{
  "id": 3,
  "match": "**.wild.example.com.",
  "exclude": ["wild.example.com.", "**.\\*.wild.example.com."],
  "types": ["A"],
  "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain"},
  "candidate": {"rcode": "NOERROR", "termination": "wildcard"},
  "witness": {
    "name": "zz-impact-0.wild.example.com.",
    "type": "A",
    "baseline": {"rcode": "NXDOMAIN", "termination": "nxdomain", "answers": [], "authority": []},
    "candidate": {
      "rcode": "NOERROR", "termination": "wildcard",
      "answers": ["zz-impact-0.wild.example.com. 300 IN A 192.0.2.60"],
      "authority": []
    }
  }
}
```

即：`wild.example.com.` 之下、除 `wild` 自身与通配符节点 `*.wild` 子树外的所有未列名，
A 查询都由 NXDOMAIN 变为通配符合成应答。

## 判定与影响分析原理

### 单版区域的应答判定（`app/resolver.py`）

对 `(qname, qtype)` 按以下顺序判定（每跳重新判定，最多 32 跳）：

1. 自 `qname` 向上找最深的非顶点 NS 节点 → `delegation`（referral，NS 入 `authority`）；
2. 名称存在：有 CNAME 且所查非 CNAME → 记入应答链并以目标重新判定；
   有所查类型 → `exact`；有其他数据 → `nodata`；无数据（ENT）→ `nodata-ent`；
3. 名称不存在：最近的 DNAME 祖先 → 记入 DNAME 记录并合成 CNAME，以重写名重新判定；
4. 最近祖先（closest encloser）存在通配符子节点 → 合成应答（`wildcard` / `nodata-wildcard`，
   通配符为 CNAME 时继续追链）；
5. 否则 `nxdomain`。链重复或超 32 跳 → `alias-loop`。

### 变更模式的计算（`app/impact.py`）

- **精确名**：两版区域中存在过的每个名称（属主名 + 空非终结点）逐一比较 6 种类型的应答。
- **间隙（gap）**：所有不存在的名称按"最近存在祖先 `a`"分组，同组内应答一致
  （仅属主名随查询名变化），用 `**.a` 排除 `a` 自身与 `a` 的各子节点子树表示；
  每组取一个代表名实际比较。
- **DNAME 传播**：若 DNAME `d → target` 在两版中都生效且一致，则 `target` 子树中的每个
  变更模式都按后缀互换 `target ↔ d` 映射回 `d` 的子树（迭代至不动点），
  从而覆盖两版区域中都未列出的名称（如示例中的 `x.d.example.com.`）。
  DNAME 新增 / 删除 / 目标变化时，其下整个子树直接作为一个变更模式。
- 具有相同（形状 + 响应码/终止原因变迁）的条目按类型分组合并为同一模式。

### 校验规则（违反即整单 400）

- 仅 `$ORIGIN`、`$TTL` 指令；仅 SOA/NS/A/AAAA/CNAME/DNAME 记录、IN 类；
- 顶点必须有唯一 SOA（SOA 不得出现在顶点之下）；
- 属主名必须在域内（dnspython 会静默丢弃越区记录，本服务显式扫描属主名拒绝）；
- NS/CNAME/DNAME 的 rdata 目标必须在域内（外部引用整单报错；SOA 的 MNAME/RNAME
  不参与解析判定，不做限制）；
- CNAME 不得与其他类型共存且只能有一条；DNAME 不得与 CNAME 共存、不得位于非顶点
  委派点、只能有一条；DNAME 节点之下不得有任何数据（RFC 6672）。

## 设计决策与限制

- **完全离线**：不做任何 DNS 网络查询；委派只给出 referral，不递归。
- 委派点之下的数据（occluded data）可解析但不参与应答（与权威服务器行为一致）。
- 应答比较包含 TTL：仅改 `$TTL` 也会体现为应答变化。
- 名称比较不区分大小写，输出统一小写；记录文本中的字面 `*` 标签在模式里转义为 `\*`。
- 否定应答的 `authority` 不附加 SOA（避免 SOA 序列号变化放大为全域变化）；
  `authority` 仅用于委派 referral 的 NS 记录。
- 别名链上限 32 跳，超限按 `alias-loop` 处理；病态 DNAME 循环下模式数量有安全上限。

## 项目结构

```
app/
  main.py       # FastAPI 入口：POST /impact、POST /resolve
  zones.py      # BIND 文本解析与校验（ZoneError → 400）
  resolver.py   # 单版区域的离线应答判定
  impact.py     # 变更模式引擎（精确名 + 间隙 + DNAME 传播）
tests/          # 单元测试 + 互斥完备性质测试 + 随机模糊测试
examples/       # README 使用的示例区域文件
Dockerfile, docker-compose.yml, requirements*.txt
```
