# tlsping

**English: [README.md](README.md)**

**HTTPS 연결 비용 진단기.** TLS 핸드셰이크를 보이게 하고, 신규 연결과 재사용 연결을 같은 시간창에서 나란히 잽니다.

```
     |  COLD  new connection         |  WARM  keep-alive |
     |   dns   tcp   tls   srv total |  wait   srv total | code
-----+-------------------------------+-------------------+-------
   2 |     0   118   129   234   482 |     0   129   129 | 200
```

이 한 줄이 전부를 말합니다. 이 엔드포인트에 새로 붙는 데 482ms가 들고 **그중 129ms가 TLS 핸드셰이크**이며, 연결이 이미 열려 있으면 같은 요청이 129ms에 끝납니다.

> ⚠️ **본인 소유이거나 측정 허가를 받은 대상에만 사용하십시오.** 반복 요청은 WAF/IPS에 어뷰징으로 기록되어 IP가 차단될 수 있습니다. 기본값(10회·1초 간격)은 안전하도록 정한 값이니 올리기 전에 한 번 더 생각하십시오.

- 의존성 없는 단일 실행 바이너리 — Go 표준 라이브러리만 사용
- Windows / Linux / macOS × amd64 / arm64
- MIT 라이선스

---

## 왜 만들었는가

접속이 느리게 느껴질 때 알고 싶은 것은 "**어느 구간이** 느린가"입니다. `ping`으로는 답이 안 나옵니다. 많은 서버가 ICMP를 아예 차단하고, 응답하더라도 ICMP는 DNS·TLS·서버 처리 시간에 대해 아무것도 말해주지 않습니다.

당연한 대안은 `httping`입니다. 훌륭한 도구이고 17년치 기능이 쌓여 있습니다. 다만 대상이 HTTPS일 때 가장 알고 싶은 두 가지를, 이 도구는 **구조적으로** 보여주지 못합니다.

**1. TLS 핸드셰이크를 절대 보여주지 않습니다.** `httping`은 `ssl_handshake`를 측정은 합니다 — 그리고 connect 시간에서 빼기만 한 뒤 **어떤 출력 모드에서도 인쇄하지 않습니다.** HTTPS 대상에서 가장 비싼 단계가 분해 결과에 없고, 그 결과 인쇄되는 5단계의 합이 총합과 맞지 않습니다.

**2. 신규 연결과 재사용 연결을 공정하게 비교할 수 없습니다.** `-Q`(keep-alive)를 붙여 두 번 실행하면 되지 않느냐는 반론이 있지만, 그 두 실행은 **서로 다른 시간창**에 놓입니다. 그 사이 네트워크 혼잡도·라우팅·서버 부하·CDN 엣지 배정이 전부 움직입니다. 관측된 차이가 "연결 재사용의 효과"인지 "그 사이 네트워크가 변한 것"인지 분리할 수 없습니다. 통제되지 않은 교란 변수(confounder)가 남습니다.

`tlsping`은 두 모드를 라운드 단위로 인터리빙하고 **매 라운드 실행 순서를 교대**합니다. 두 모드가 같은 시간창을 공유하므로 교란 변수가 양쪽에 균등 분산되어 상쇄됩니다. 이것이 **paired 비교**이며, 도구를 두 번 실행하는 방식(unpaired)보다 통계적으로 강한 설계입니다.

그래서 이 도구가 답하는 질문은 좁고 구체적입니다.

> **이 HTTPS 엔드포인트에 처음 붙는 비용은 얼마이고, 그중 TLS가 얼마이며, 연결이 이미 열려 있으면 얼마나 빨라지는가?**

---

## 설치

URL, TLS, 인증서 경로에 필요한 표준 라이브러리 보안 수정이 포함된 Go 1.26.6
이상이 필요합니다.

직접 설치하려면 다음을 실행하십시오.

```sh
go install github.com/drvoss/tlsping@latest
```

또는 로컬 clone에서 빌드하십시오.

```sh
# 이 저장소를 로컬에 clone한 위치에서:
go build -o tlsping .
```

산출물은 의존성 없는 단일 실행 파일이므로 `PATH` 어디에나 두면 됩니다. 크로스 컴파일도 Go 툴체인만 있으면 됩니다.

```sh
GOOS=linux   GOARCH=arm64 go build -o dist/tlsping-linux-arm64      .
GOOS=darwin  GOARCH=arm64 go build -o dist/tlsping-darwin-arm64     .
GOOS=windows GOARCH=amd64 go build -o dist/tlsping-windows-amd64.exe .
```

> **사전 빌드된 바이너리는 아직 없습니다.** 현재는 소스 빌드가 유일한 설치 경로입니다. [프로젝트 상태](#프로젝트-상태)를 참고하십시오.

---

## 빠른 시작

```
tlsping [flags] <host|url>
```

```
$ tlsping -n 8 -i 400ms example.com

HEAD https://example.com/ -> 172.66.147.243:443   h2 · TLS1.3 · 0 bytes
8 rounds, 400ms interval, order=alternate; all times in ms, "-" = not measured

     |  COLD  new connection         |  WARM  keep-alive |
     |   dns   tcp   tls   srv total |  wait   srv total | code
-----+-------------------------------+-------------------+-------
   1 |     0   116   241   233   593 |   357   241   599 | 200      warmup·new conn
   2 |     0   118   129   234   482 |     0   129   129 | 200
   3 |     0   117   128   235   481 |     0   126   126 | 200
   4 |     2   119   508   237   868 |     0   121   121 | 200
   5 |     0   117   123   234   476 |     0   125   126 | 200
   6 |     2   117   122   234   476 |     0   124   125 | 200
   7 |     0   118   123   236   478 |     0   124   125 | 200
   8 |     0   121   122   233   477 |     0   123   124 | 200

--- example.com  statistics ---
  n = 7 (warmup 1 excluded), elapsed 6.6s
                        cold        warm
  ok / sent              7/7         7/7
  loss                  0.0%        0.0%
  min                  476ms       121ms
  mean                 534ms       125ms
  median               478ms       125ms
  max                  868ms       129ms
  mdev                 136ms         2ms
  p95                      -           -
  (p95 needs n >= 20)

  handshake overhead  =  +243ms   median(dns+tcp+tls) per cold sample
    dns 0ms · tcp 118ms · tls 123ms  (per-stage medians)
  keep-alive gain     =  +353ms   median(cold.total) - median(warm.total)  [reference]
```

**이 출력을 읽는 법**

- 1라운드의 `tls 241`이 2라운드부터 `~123`으로 떨어집니다. **TLS 세션 재개(session resumption)** 입니다. 두 번째 핸드셰이크는 세션 티켓을 재사용해 왕복 한 번을 건너뜁니다. `httping`이 숨기는 값이 정확히 이것입니다.
- 이 엔드포인트에 cold로 붙는 데 약 478ms가 들고, 그중 243ms가 순수 핸드셰이크 비용(`dns + tcp + tls`)입니다. 연결을 재사용하면 125ms로 끝납니다.
- 4라운드에서 `tls 508`로 튀었습니다. 이 한 번의 핸드셰이크가 `mean`(534)을 `median`(478)보다 한참 위로 끌어올렸고 `mdev`를 136ms로 밀었습니다. **mean과 median의 벌어짐 자체가 신호입니다** — 안정적인 엔드포인트는 둘이 붙어 있습니다.
- `warmup` 라운드는 모든 통계에서 제외됩니다. 첫 warm 요청은 공유 연결이 아직 없어 반드시 직접 dial해야 하며, `new conn` 비고와 큰 `wait 357`이 그 의미입니다.

---

## 무엇을 재는가

| 단계 | 키 | 측정 구간 | 의미 |
|---|---|---|---|
| DNS | `dns` | `LookupNetIP` 직접 실측 | 리졸버 성능 (네트워크 RTT와 무관) |
| 풀 대기 | `wait` | `GetConn` → `GotConn` | 커넥션 풀에서 연결을 받기까지의 대기 |
| TCP | `tcp` | `ConnectStart` → `ConnectDone` | RTT **근사값** ([한계](#알려진-한계) 참고) |
| TLS | `tls` | `TLSHandshakeStart` → `Done` | RTT 1~2회 + 암호 연산 |
| 서버 | `srv` | `WroteRequest` → `GotFirstResponseByte` | RTT 1회 + 서버 자체 처리 시간 |
| 전체 | `total` | 모드별 기점 → body EOF | 독립적으로 측정한 실제 소요 시간 |

### 두 모드는 다르게 분해된다

`wait`는 `GetConn` → `GotConn` 구간인데, **새 연결**을 만드는 경우 이 구간이 dial과 TLS 핸드셰이크를 통째로 삼킵니다. `dns + wait + tcp + tls + srv`로 합산하면 이중 계산이 됩니다. 그래서 모드마다 서로 겹치지 않는 분해식을 따로 씁니다.

```
cold (새 연결)      기점 = DNS 조회 시작
                    total = dns + tcp + tls + srv + other
                    wait 은 기록하지 않는다 ("-")

warm (연결 재사용)   기점 = Client.Do 호출 직전
                    total = wait + srv + other
                    dns/tcp/tls 는 발생하지 않는다 ("-")
```

`total`은 단계 합이 아니라 독립 측정값이므로 항상 `total ≥ 단계 합`이 성립합니다. 잔여 구간이 `other`(요청 헤더 전송, 본문 수신, 런타임 내부 처리)이며 `-v`에서 표시됩니다. `other`가 `total`의 20%를 넘으면 경고합니다.

**표의 `-`는 0ms가 아니라 "미측정"입니다.** 오류 경로에서 일부 단계까지만 도달하는 것은 정상이며, 그대로 정직하게 보고합니다.

### warm은 왜 필요한가

cold 분해만으로도 핸드셰이크 비용은 이미 나옵니다. warm은 그것으로 알 수 없는 세 가지를 잽니다.

1. **서버가 실제로 keep-alive를 지켜주는가?** 연결을 끊는 서버는 `new conn` 카운터로 드러납니다.
2. **연결이 살아 있을 때 서버 처리 시간(`srv`)이 달라지는가?** HTTP/2 멀티플렉싱이나 서버 측 세션 상태가 이 값을 움직일 수 있습니다.
3. **재사용 시 커넥션 풀 경합(`wait`)이 발생하는가?**

> **TLS 세션 재개 효과는 warm이 아니라 cold에서 나타납니다.** warm은 keep-alive 재사용이라 핸드셰이크 자체가 일어나지 않고 `tls`는 미측정입니다. 티켓 재사용은 cold의 `tls`가 2회차부터 낮아지는 형태로 관찰됩니다.

### 통계

- **`mdev`는 모집단 표준편차**이며, iputils `ping`이 같은 이름으로 인쇄하는 값과 정의가 같습니다. 이름과 달리 평균절대편차가 아닙니다.
- **`p95`는 n ≥ 20에서만 산출합니다.** n=4에서의 95백분위는 max와 같아 정보량이 없습니다. 백분위는 nearest-rank(보간 없음)를 씁니다.
- **`handshake overhead`는 각 cold 샘플 *내부*에서 `dns + tcp + tls`를 더한 값의 median입니다.** 동일 요청 안의 합이라 통계적으로 정당하며, Duration의 합이므로 음수가 될 수 없습니다. 그 아래 인쇄되는 단계별 median의 합이 이 값과 일치하지 않는 것은 정상입니다 — 합의 median은 median의 합이 아닙니다.
- **`keep-alive gain`은 `median(cold.total) − median(warm.total)`이며, 일부러 `[reference]`로 표시됩니다.** 서로 다른 분포의 백분위를 감산한 값은 정식 통계량이 아닙니다. `-v`에서는 라운드별 paired 차이의 median을 함께 내는데, 이쪽이 통계적으로 방어 가능한 값입니다.

### 성공과 실패

| 분류 | 조건 | 처리 |
|---|---|---|
| 성공 | HTTP 응답을 받음 (상태코드 무관: 2xx/3xx/4xx/5xx 전부) | 시간 통계에 포함 |
| 실패 | 응답을 받지 못함 — DNS 실패, 연결 거부, TLS 오류, 타임아웃, body 읽기 오류 | loss로 집계, 시간 통계에서 제외 |

4xx/5xx를 실패로 세지 않는 이유는 이 도구가 가용성이 아니라 **지연**을 재기 때문입니다. 404가 와도 왕복 시간은 유효한 측정값입니다.

warm에서 `Reused == false`인 샘플도 **실패가 아닙니다.** ok로 세되 시간 통계에서 빼고 `new conn` 카운터로 보고합니다. 이 값이 크면 서버가 연결을 유지하지 않는다는 뜻이며, 그 자체가 유용한 정보입니다.

**첫 warm 요청은 반드시 `Reused == false`입니다.** 공유 Transport에 아직 연결이 없어 그 요청이 직접 dial과 핸드셰이크를 수행하기 때문이며, `--warmup` 기본값이 1인 이유가 이것입니다.

---

## 출력

### 기호

`-`는 자리마다 뜻이 다릅니다. 혼동하지 마십시오.

| 위치 | `-`의 의미 |
|---|---|
| 단계 칸 (`dns`/`tcp`/`tls`/`wait`) | **미측정.** 0ms가 아닙니다. 해당 모드가 그 단계를 지불하지 않았거나, 오류로 거기까지 가지 못했습니다 |
| `code` 칸의 `-/200` | 왼쪽이 **cold**, 오른쪽이 **warm**. `-`는 그쪽이 응답을 받지 못했다는 뜻입니다 |
| `p95` 행 | 유효 표본이 20개 미만이라 산출하지 않음 |
| `min`/`mean`/… 행 | 시간 통계에 넣을 수 있는 샘플이 하나도 없음 |

`warmup` 비고가 붙은 라운드는 모든 통계에서 제외됩니다. 요약의 `n = 7 (warmup 1 excluded)`가 그 결과입니다.

### 실패했을 때

실패한 모드의 칸만 사유로 채우고 반대편은 정상 출력합니다. loss는 cold/warm 각각 독립 집계됩니다.

```
   5 |     0    34    71    41   148 |     1    40    42 | 200
   6 |         timeout (5s)          |     0    33    34 | -/200
```

6라운드는 cold가 타임아웃했고 warm은 34ms로 정상 응답했습니다. `code`의 `-/200`이 정확히 그것을 말합니다.

사유 문자열: `timeout (5s)`, `conn refused`, `conn reset`, `dns fail`, `unreachable`, `TLS: cert expired`, `TLS: cert name`, `TLS: unknown CA`, `TLS: cert invalid`, `TLS error`, `conn closed`, `body error`, `canceled`.

### 좁은 터미널

터미널 폭에 따라 레이아웃이 자동 선택됩니다. `COLUMNS`로 강제할 수 있습니다.

**70~99열** — 라운드마다 2줄 스택:

```
  #2   COLD dns    0 tcp   31 tls   63 srv   32 =   128ms 200
       WARM wait   0                   srv   32 =    33ms 200
```

**70열 미만** — cold 블록 전체를 출력한 뒤 warm 블록:

```
COLD
   2 dns    0 tcp   31 tls   63 srv   32 = 128ms 200
   3 dns    0 tcp   33 tls   67 srv   38 = 140ms 200

WARM
   2 wait   0 srv   32 = 33ms 200
   3 wait   0 srv   37 = 38ms 200
```

최소 레이아웃에서는 한 줄에 cold와 warm을 나란히 놓는 짝 대조가 사라집니다. 짝 비교가 필요하면 터미널을 넓히거나 `--json`을 쓰십시오.

### `-q` 와 `-v`

`-q`는 **표만** 총합과 상태코드로 줄입니다. 통계 블록은 그대로 전부 나옵니다. 6칸으로는 사유를 자르지 않고 담을 수 없으므로, 실패 사유는 칸 대신 줄 끝 비고로 이동합니다.

```
     |  COLD |  WARM |
     | total | total | code
-----+-------+-------+-------
   6 |   err |    34 | -/200    cold timeout (5s)
```

`-v`는 라운드마다 `other` 잔여 구간과 TLS 재개 여부를 붙이고, 요약에 paired gain·`new conn` 카운터·인증서 체인 길이·ALPN·overhead 집계에서 제외된 샘플 수를 덧붙입니다. `-q`와 `-v`는 함께 쓸 수 없습니다.

---

## 플래그

| 플래그 | 기본 | 설명 |
|---|---|---|
| `-n, -c, --count N` | `10` | 측정 횟수. `0`이면 Ctrl+C까지 무한 |
| `-i, --interval D` | `1s` | 라운드 간격. 하한 `200ms` 강제 |
| `-w, --timeout D` | `5s` | 요청당 타임아웃 (DNS부터 body EOF까지 전 구간) |
| `-m, --mode M` | `both` | `both` \| `cold` \| `warm` |
| `--order O` | `alternate` | `cold-first` \| `warm-first`로 순서를 고정할 수 있음 |
| `--warmup N` | `1` | 통계에서 제외할 선행 **라운드** 수 |
| `-X, --method M` | 자동 | 미지정 시 HEAD로 시작하고, 405/501이면 `GET` + `Range: bytes=0-0` |
| `--http-version V` | `auto` | `1.1` \| `2`. **`3`은 미지원**이며 종료 코드 3으로 끝납니다 |
| `--cache-bust` | off | 요청마다 `?_=<seq>` 부착 |
| `--no-pin-ip` | — | IP 고정 해제, 라운드마다 재조회 (고정이 기본) |
| `-4` / `-6` | auto | IP 버전 강제 |
| `-k, --insecure` | off | 인증서 검증 생략 |
| `-H, --header 'N: v'` | — | 커스텀 요청 헤더, 반복 지정 가능 |
| `--json` / `--csv` | — | 기계 판독 출력. 동시 지정 시 오류 |
| `--no-color` | — | ANSI 색상 비활성 (`NO_COLOR`도 존중) |
| `-q, --quiet` | — | 표를 총합과 상태코드만으로 축약 |
| `-v` | — | 잔여 구간, TLS 세부, paired gain, new conn 카운터 |
| `--version` | — | 버전 출력 |

**입력 정규화**: `google.com` → `https://google.com/`. 스킴을 생략하면 https가 기본입니다.

### 종료 코드

| 코드 | 조건 |
|---|---|
| `0` | 측정한 모든 샘플이 응답을 받음 |
| `1` | 일부 샘플이 응답을 받지 못함 |
| `2` | 모든 샘플이 실패, 프리플라이트 실패, 또는 출력을 쓰지 못함 |
| `3` | 사용법 오류 |

판정 대상은 **warmup을 제외한** 샘플입니다(warmup밖에 없으면 그것으로 판정). 상태코드는 판정에 쓰이지 않습니다 — 404도 유효한 왕복 시간을 얻었기 때문입니다.

**조기 중단은 종료 코드에 나타나지 않습니다.** `429`·`503 + Retry-After`·연속 실패 방지로 실행이 일찍 끊겨도, 얻은 샘플이 모두 성공이면 코드는 `0`입니다. 자동화에서는 stderr 경고, 또는 `--json`의 `warnings[]`와 `samples` 개수로 중단 여부를 판단하십시오.

---

## 기계 판독 출력

### `--json`

실행이 끝나면 stdout에 문서 하나를 냅니다. `schema` 필드가 형식 버전이며 호환되지 않는 변경 시 올라갑니다.

```sh
tlsping -n 20 --json example.com | jq '.summary.cold.median_ms'
tlsping -n 20 --json example.com | jq -r '.samples[] | select(.mode=="cold") | .tls_ms'
tlsping --json example.com | jq '.summary.handshake_overhead_ms'
```

| 필드 | 의미 |
|---|---|
| `schema` | 형식 버전 (현재 `1`) |
| `run` | 대상, 확정된 메서드·주소·프로토콜·TLS 버전, 사용된 설정값 |
| `samples[]` | 샘플별 단계. **미측정 구간은 `null`** 이며 `0`과 구분됩니다 |
| `samples[].error_kind` | 안정적인 실패 코드 — `timeout`, `conn_refused`, `dns_fail`, `cert_expired`, `cert_name`, `cert_unknown_ca`, `cert_invalid`, `tls_error`, `conn_closed`, `conn_reset`, `unreachable`, `body_error`, `canceled`, `error` |
| `samples[].error` | 원본 오류 문자열 — 표시용이며 버전 간 안정성을 보장하지 않습니다 |
| `samples[].cert_chain_len` | 실제로 핸드셰이크가 일어난 샘플에만 존재 |
| `summary` | cold/warm 집계, overhead 분해, gain, paired gain, 세션 재개 횟수 |
| `warnings[]` | stderr로도 나간 경고 |

모든 시간 필드는 밀리초이며 소수점 이하를 포함합니다. n < 20이면 `p95_ms`는 `null`입니다.

파싱은 `error`가 아니라 `error_kind`로 하십시오. 전자는 자유 문자열이고, 후자가 스키마의 일부입니다.

### `--csv`

샘플 한 건당 한 행을 **스트리밍**합니다. 요약은 포함되지 않으므로 필요하면 `--json`을 쓰십시오. 미측정 구간은 빈 필드입니다.

```
round,mode,warmup,dns_ms,tcp_ms,tls_ms,wait_ms,srv_ms,total_ms,other_ms,reused,
new_conn,retries,status,proto,tls_version,alpn,tls_resumed,cert_chain_len,bytes,
addr,body_overflow,error_kind,error
```

---

## 동작 방식

**프리플라이트.** 측정 시작 전에 요청 1회를 보내 두 가지를 확정합니다. 하나는 메서드(HEAD가 405/501이면 Range를 붙인 GET으로 폴백), 다른 하나는 연결을 맺어야만 알 수 있는 것들 — 실제 접속 IP, 협상된 프로토콜, TLS 버전입니다. HEAD→GET 폴백을 라운드 중에 하면 한 라운드가 두 연결을 쓰게 되어 연결 수 불변식이 깨지므로 라운드 밖으로 뺐습니다. 프리플라이트는 모든 통계에서 제외되며, 실패하면 아무것도 측정하지 않고 종료 코드 2로 끝냅니다.

**IP 고정 (기본 on).** 프리플라이트에서 확정한 주소를 실행 내내 dial 대상으로 씁니다. 라운드로빈 DNS나 애니캐스트 뒤에서는 cold와 warm이 서로 다른 서버를 재게 되어 대조 자체가 무의미해지기 때문입니다. **URL의 호스트명은 그대로 유지**되므로 SNI와 인증서 검증은 정상 동작합니다. 고정 시 프록시는 비활성화되며, 프록시 환경이 감지되면 경고합니다.

**DNS.** IP 고정이 켜져 있으면 `DialContext`가 이미 IP를 받으므로 httptrace의 DNS 훅이 아예 호출되지 않습니다. 그래서 `LookupNetIP`로 직접 실측하며, cold 프로브의 첫 단계로 수행합니다. 이 조회는 시간을 재기 위한 것이고 `--no-pin-ip`가 아닌 한 dial 대상을 바꾸지 않습니다.

**cold 격리.** 라운드마다 새 `http.Transport`, `DisableKeepAlives`, 사용 후 `CloseIdleConnections()`. 격리되는 것은 **커넥션 풀뿐**입니다 — [알려진 한계](#알려진-한계)를 보십시오.

**리다이렉트는 추종하지 않습니다.** 추종하면 한 논리 요청에 트레이스 훅이 홉마다 반복되어 여러 연결의 시간이 한 샘플에 섞입니다. 3xx도 유효 응답으로 집계하며, 첫 응답이 리다이렉트면 `Location` 대상을 stderr에 안내해 최종 URL로 다시 실행할 수 있게 합니다.

**안전장치.** `429` 또는 `503 + Retry-After` 수신 시 즉시 중단, 연속 실패 3회 시 중단, 간격 하한 200ms, 그리고 서버 운영자가 식별할 수 있도록 `tlsping/<버전>` User-Agent를 보냅니다.

---

## 알려진 한계

수치를 과대 해석하지 않도록 명시합니다.

| 항목 | 내용 |
|---|---|
| **`tcp`는 ICMP RTT가 아니다** | 서버의 listen backlog 지연과 방화벽 SYN 필터링이 섞여 있습니다. 근사값으로만 읽으십시오. |
| **TTL 없음** | Go의 `net/http`는 IP 헤더를 노출하지 않아 `ping`의 `TTL=`에 해당하는 값이 없습니다. 상태코드와 협상 프로토콜이 그 자리를 대신합니다. |
| **OS DNS 캐시** | 2회차부터 `dns`가 거의 0이 됩니다. 실질적으로 첫 샘플만 의미가 있습니다. |
| **cold는 커넥션 풀만 격리한다** | OS DNS 캐시, TLS 세션 티켓, 서버 측 상태는 격리되지 않습니다. 특히 **cold Transport들은 TLS 세션 캐시를 공유**하므로 2회차 이후의 `tls`는 *재개된* 핸드셰이크입니다. 이는 의도된 설계이며(그래야 재개 효과가 관찰됩니다), `-v`의 `tls resumed`로 확인할 수 있습니다. 매번 완전한 최초 핸드셰이크를 원한다면 프로세스를 여러 번 실행하십시오. |
| **HTTP/2에서의 `Reused`** | h2에서 `Reused == true`는 "기존 연결 위의 새 스트림"이라는 뜻이며 독점 연결을 보장하지 않습니다. |
| **캐시버스팅은 무력화될 수 있다** | CDN이 `?_=`를 무시하고 캐시 응답을 줄 수 있고, WAF가 이 패턴을 스캔으로 읽을 수도 있습니다. 그래서 기본 off입니다. |
| **`--no-pin-ip` + 프록시** | `tcp`가 프록시까지의 시간이 되고, `dns`는 실제 경로와 무관한 값을 재게 됩니다. |
| **`--no-pin-ip` + `-m both`** | cold는 매 라운드 조회 결과를 따르고 warm은 처음 잡은 연결을 유지하므로, 라운드로빈 DNS에서 두 모드가 다른 서버를 잴 수 있습니다. 실행 시 경고합니다. |
| **본문 상한 64KiB** | 초과하면 본문을 다 읽을 수 없어 연결을 재사용할 수 없고(HTTP/1.x는 완전 소진 필요), warm이 매번 새로 dial합니다. 이때 경고합니다. |
| **색상 임계값** | 출력이 라이브 append이므로 "median×1.5" 강조는 **그 시점까지 본 샘플의 median** 기준입니다. |

---

## 비목표

의도적으로 만들지 않는 것들입니다. 기능 폭을 넓히면 이 도구의 초점이 사라집니다.

- **부하 테스트 도구가 아닙니다** — 동시성 1, 기본 10회
- **모니터링 데몬이 아닙니다** — one-shot CLI입니다. Nagios 모드 대신 `--json`과 종료 코드로 대응하십시오
- **대역폭 측정기가 아닙니다** — 기본이 HEAD입니다
- 프록시/SOCKS5, TCP Fast Open, TOS/priority, MTU 제어, 쿠키, 웹 인증, FFT 그래프는 명시적 비목표입니다
- HTTP/3, 리다이렉트 추종(`--follow`), 다중 호스트 비교, TUI는 이후 릴리스로 미뤘습니다

이런 기능이 필요하다면 [`httping`](https://www.vanheusden.com/httping/)에 이미 있을 가능성이 높습니다.

---

## 프로젝트 상태

**v0.1.0 — 초기 단계입니다.** 측정 코어는 테스트되어 있고 불변식은 회귀 테스트로 강제되지만, 아직 폭넓은 실사용을 거치지 않았습니다.

- **CLI 플래그와 `--json`/`--csv` 스키마는 v1.0 전까지 바뀔 수 있습니다.** `schema`가 버전으로 관리되므로 소비자는 이를 고정해 쓸 수 있습니다.
- 사전 빌드 바이너리와 패키지 매니저 배포는 아직 없습니다.
- Windows에서 검증했고, Linux·macOS의 amd64/arm64로 크로스 컴파일을 확인했습니다. Linux와 macOS 실사용 보고를 특히 환영합니다.

---

## 개발

```sh
go build ./...
go vet ./...
go test -race ./...                 # -race 는 선택이 아닙니다
go test ./internal/render -update    # 골든 파일 갱신
```

트레이스 훅은 동시에 호출될 수 있으므로(HTTP/2 스트림, Happy Eyeballs) **`-race`는 권장이 아니라 요구사항입니다.** Windows에서는 cgo가 필요하니 mingw-w64 같은 C 컴파일러를 `PATH`에 두고 `CGO_ENABLED=1`로 실행하십시오.

최우선 회귀 테스트는 **연결 수 불변식**입니다. cold N회는 서버가 보는 연결이 정확히 N개, warm N회는 정확히 1개여야 합니다. 이게 깨지면 도구가 인쇄하는 모든 숫자가 무의미해집니다. `TestColdOpensOneConnectionPerProbe`와 `TestWarmReusesOneConnection`을 보십시오.

```
main.go                     진입점: 파싱 → 실행 → 종료 코드
internal/cli/               플래그, 검증, URL 정규화
internal/probe/             httptrace 수집, cold/warm 러너, 스케줄러
internal/stats/             백분위, mdev, 집계
internal/render/            표 레이아웃, 색상, JSON/CSV
```

의존은 한 방향으로만 흐릅니다: `render → stats → probe`. `probe`가 공유 데이터 타입을 전부 소유하며 나머지 둘을 import하지 않습니다.

기여를 환영합니다. 큰 변경 전에는 이슈를 먼저 열어 주십시오 — [비목표](#비목표) 목록은 의도적인 것이라, 범위를 넓히는 PR은 품질과 무관하게 거절될 가능성이 높습니다.

## 라이선스

MIT — [LICENSE](LICENSE) 참조.

`httping`은 GPL 라이선스이며 그 코드는 tlsping에 포함되어 있지 않습니다.
