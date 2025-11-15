# URL 단축 서비스 API (Cloudflare Worker)

이 프로젝트는 Cloudflare Workers를 사용하여 구축된 URL 단축 서비스의 백엔드 API입니다. Google OAuth 2.0을 통한 사용자 인증, 다양한 종류의 리디렉션, 커스텀 URL 생성 등 고급 기능을 제공합니다.

## 🚀 주요 기능

-   **사용자 인증**: Google OAuth 2.0을 통해 사용자를 인증하고, 계정별 고유 API 키를 발급합니다.
-   **URL 단축**:
    -   **익명 단축**: 인증 없이 무작위 코드를 사용한 기본 단축 URL을 생성합니다.
    -   **사용자별 단축**: 인증된 사용자는 `사용자ID/` 접두사가 붙는 URL을 생성하여 자신의 링크를 관리할 수 있습니다.
    -   **커스텀 Alias**: 인증된 사용자는 `사용자ID/나만의-alias` 형식으로 URL을 직접 지정할 수 있습니다.
-   **다양한 서비스 타입**:
    -   **`r1`**: 만료 시간이 지정된 URL.
    -   **`r3`**: 표준 리디렉션 URL (기본값).
    -   **`r5`**: 파일 크기에 따라 트래픽 쉐이핑(속도 제한)이 적용되는 URL.
-   **CORS 지원**: 모든 API 응답에 CORS 헤더를 포함합니다.

## 🛠️ API 엔드포인트

### 1. `POST /api/member`

Google OAuth 2.0 인증 콜백을 처리하여 사용자를 등록/로그인하고 API 키를 발급합니다.

-   **요청 본문**: `code`, `code_verifier`, `redirect_uri`
-   **성공 응답**: `tokens`, `profile` (사용자 정보), `apiKey`, `uniqueUserId`

---

### 2. `POST /api/shorten`

URL을 단축하거나 기존 단축 URL을 수정합니다.

-   **헤더**: `Authorization: Bearer <API_KEY>` (커스텀 alias 등 사용자 기능에 필요)
-   **요청 본문**:
    -   `url` (string, **필수**): 단축할 원본 URL.
    -   `alias` (string, 선택): 커스텀 경로. 인증된 사용자만 사용 가능.
    -   `type` (string, 선택): 서비스 타입 (`r1`, `r3`, `r5`). 기본값은 `r3`.
    -   `expiresAt` (string, `r1` 타입 필수): URL 만료 시간 (ISO 형식).
-   **성공 응답**: `ok`, `code` (단축 코드), `message`, `shortUrl` (완성된 단축 URL).

## ⚙️ 서비스 타입 (`type`) 상세

-   **`r1` (Time-based)**: `expiresAt`으로 지정된 시간에 만료됩니다. 원본 URL에 `cnt` 파라미터가 없으면 `cnt=${cnt}` 플레이스홀더를 추가합니다.
-   **`r3` (Standard)**: 기본 리디렉션 타입입니다.
-   **`r5` (Traffic Shaping)**: 대용량 파일 공유에 적합합니다. 파일 크기에 따라 리디렉션 URL에 속도 제한 파라미터를 추가합니다.

## 🗄️ 데이터 저장소 (Cloudflare KV)

-   `RES302_KV`: 단축 코드와 원본 URL 매핑.
-   `REQ_TIME_KV`: `r1` 타입의 만료 시간.
-   `USER_KV`: 사용자 프로필 정보.
-   `API_KEY_TO_SUB_KV`: API 키와 사용자 ID 매핑.
-   `GOOGLE_SUB_TO_USER_ID_KV`: Google ID와 사용자 ID 매핑.

## 🔑 환경 변수

-   `GOOGLE_CLIENT_ID`: Google OAuth Client ID.
-   `GOOGLE_SECRET`: Google OAuth Client Secret.
-   `TEST_API_KEY`: 개발 및 테스트용 API 키.

## 🏗️ 코드 구조

-   `handleRequest`: 모든 요청의 라우터. 경로에 따라 적절한 핸들러로 분기합니다.
-   `handleShorten`: URL 단축/수정의 핵심 로직을 처리합니다.
-   `handleAuthCallback`: Google OAuth 인증 후 API 키를 생성하고 사용자 정보를 저장합니다.
-   `validateApiKey`: `Authorization` 헤더의 API 키를 검증합니다.