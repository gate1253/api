const CODE_KEY = 'RES302_codes_list_v1'; // KV에 저장되는 메타 리스트 키

//API 
function makeCode(len=6){
	const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	let s='';
	for(let i=0;i<len;i++) s+=chars[Math.floor(Math.random()*chars.length)];
	return s;
}

// 추가: 12자리 고유 회원 ID 생성 함수
function makeUniqueId(len = 12) {
    const arr = new Uint8Array(Math.ceil(len * Math.log2(36) / 8)); // base36에 필요한 바이트 수 계산
    crypto.getRandomValues(arr);
    let s = '';
    for (let i = 0; i < arr.length; i++) {
        s += (arr[i] % 36).toString(36); // base36으로 변환
    }
    return s.slice(0, len);
}

// 추가: API 키 생성 함수 (더 긴 길이)
function makeApiKey(len = 32) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < len; i++) {
        key += chars[Math.floor(Math.random() * chars.length)];
    }
    return key;
}

// 변경: CORS 유틸 추가
function corsHeaders() {
	return {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		'Access-Control-Max-Age': '86400'
	};
}
function jsonResponse(obj, status = 200, extraHeaders = {}) {
	const headers = Object.assign({}, corsHeaders(), {'Content-Type':'application/json'}, extraHeaders);
	return new Response(JSON.stringify(obj), {status, headers});
}

// 추가: API 키 검증 함수
async function validateApiKey(request, env) {
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		// 401: 인증 자격 증명 없음
		return jsonResponse({ error: 'API 키가 필요합니다. Authorization 헤더에 Bearer 토큰을 포함해주세요.' }, 401);
	}
	const apiKey = authHeader.slice(7); // "Bearer " 제거

	// 추가: 테스트용 API 키 허용
	// 환경 변수(TEST_API_KEY)에 정의된 키와 일치하면, KV 조회 없이 즉시 통과시킵니다.
	if (env.TEST_API_KEY && apiKey === env.TEST_API_KEY) {
		// brand/index.html의 테스트용 사용자 정보를 참조한 모의 사용자 데이터를 반환합니다.
		return {
			user: {
				uniqueUserId: 'test-user-id-for-viewing-456',
				name: 'Test User',
				picture: 'https://lh3.googleusercontent.com/a/default-user=s96-c',
				apiKey: env.TEST_API_KEY, // 현재 사용된 API 키를 그대로 반환
			},
		};
	}

	// API_KEY_TO_SUB_KV에서 API 키로 uniqueUserId를 찾음
	const uniqueUserId = await env.API_KEY_TO_SUB_KV.get(apiKey);
	if (!uniqueUserId) {
		// 403: 제공된 키가 저장소에 없어 접근이 거부됨
		return jsonResponse({ error: '유효하지 않은 API 키입니다.' }, 403);
	}

	// USER_KV에서 uniqueUserId를 기반으로 사용자 데이터 검증
	const userData = await env.USER_KV.get(`user:${uniqueUserId}`, { type: 'json' });
	if (!userData || userData.apiKey !== apiKey) {
		return jsonResponse({ error: '사용자 정보가 일치하지 않거나 키가 만료되었습니다.' }, 403);
	}
	return { user: userData }; // 성공 시 사용자 데이터 반환
}


async function handleShorten(req, env){
	try{
		const body = await req.json(); // 요청 본문 파싱
		let {url, alias, type} = body; // 변경: type 파라미터 추가
		if(!url) return jsonResponse({error:'url 필요'}, 400);
		// 간단한 url 보정
		if(!/^https?:\/\//i.test(url)) url = 'https://' + url;
		
		// 추가: type에 따라 동적으로 shortUrl 생성
		const validTypes = ['r1', 'r2', 'r3', 'r5'];
		const serviceType = validTypes.includes(type) ? type : 'r3'; // type이 없거나 유효하지 않으면 'r3'를 기본값으로 사용

		let code; // 최종적으로 KV에 저장될 코드 (alias 또는 랜덤)
		let fullRedirectPath; // 응답 및 CODE_KEY에 저장될 전체 경로 (code 또는 uniqueUserId/alias)
		let operationType = 'create'; // 'create' 또는 'update'
		let uniqueUserIdFromApiKey = null; // API 키로 확인된 사용자 ID

		if(alias){ // 커스텀 코드가 제공된 경우
			const validationResult = await validateApiKey(req, env);
			if (validationResult instanceof Response) { // Response 객체이면 오류이므로 그대로 반환
				return validationResult;
			}
            // 변경: API 키로 검증된 사용자의 uniqueUserId를 직접 사용
            uniqueUserIdFromApiKey = validationResult.user.uniqueUserId;

            code = alias.trim();
            // 추가: 커스텀 코드(alias)에 선행 '/'가 있으면 제거
            if (code.startsWith('/')) {
                code = code.substring(1);
            }
            if (!code) { // '/'만 있었거나 trim 후 비어있는 경우
                return jsonResponse({error: '유효하지 않은 커스텀 코드입니다.'}, 400);
            }

            fullRedirectPath = `${uniqueUserIdFromApiKey}/${code}`; // 리다이렉트 경로에 검증된 uniqueUserId 사용
            
            // KV에서 사용자별 alias 존재 여부 확인
            const existingUrl = await env.RES302_KV.get(fullRedirectPath); // KV 키 변경
            if(existingUrl){
                operationType = 'update';
                if (existingUrl === url) {
                    return jsonResponse({ok:true, code: fullRedirectPath, shortUrl: `${new URL(req.url).origin}/${fullRedirectPath}`, message: 'URL이 이미 존재하며 변경사항이 없습니다.'}, 200);
                }
            }
		} else { // alias가 제공되지 않은 경우 (무작위 코드 생성)
			// 추가: API 키가 있으면 사용자 인증 시도
			const authHeader = req.headers.get('Authorization');
			if (authHeader && authHeader.startsWith('Bearer ')) {
				const validationResult = await validateApiKey(req, env);
				if (validationResult instanceof Response) {
					return validationResult; // 유효하지 않은 키는 에러 처리
				}
				uniqueUserIdFromApiKey = validationResult.user.uniqueUserId;
			}

			for(let i=0;i<6;i++){
				const c = makeCode();
				// 사용자가 인증된 경우, 사용자별 경로로 충돌 확인. 아니면 글로벌 경로로 확인.
				const checkPath = uniqueUserIdFromApiKey ? `${uniqueUserIdFromApiKey}/${c}` : c;
				if(!(await env.RES302_KV.get(checkPath))){
					code = c; break;
				}
			}
			if(!code) code = makeCode(8); // 6번 시도 후에도 코드 생성 실패 시 대체

			if (uniqueUserIdFromApiKey) {
				fullRedirectPath = `${uniqueUserIdFromApiKey}/${code}`;
			} else {
				fullRedirectPath = code; // 익명 사용자는 이전과 같이 글로벌 경로 사용
			}
		}
		
		// KV에 저장할 최종 URL 값
		let urlToStore = url;

		if (serviceType === 'r5') {
			// r5 타입은 r2 서비스로 리디렉션되도록, 내부적으로 r2를 호출하여 그 결과 URL을 저장합니다.
			const newBody = { ...body, type: 'r2', alias: undefined };
			const newReq = new Request(req, { body: JSON.stringify(newBody) });
			
			const r2Response = await handleShorten(newReq, env);
			if (!r2Response.ok) return r2Response; // r2 처리 중 오류 발생 시 그대로 반환

			const r2Result = await r2Response.json();
			urlToStore = r2Result.shortUrl; // r2로 생성된 shortUrl (예: https://r2.ggm.kr/...)을 저장할 값으로 설정
		}

		// KV에 URL 저장/업데이트 (fullRedirectPath를 키로 사용)
		await env.RES302_KV.put(fullRedirectPath, urlToStore);

		// 메타 리스트(CODE_KEY) 업데이트
		const raw = await env.RES302_KV.get(CODE_KEY);
		let list = raw ? JSON.parse(raw) : [];

		if (operationType === 'update') {
			const index = list.findIndex(item => item.code === fullRedirectPath); // fullRedirectPath로 찾음
			if (index !== -1) {
				list[index].url = urlToStore;
				list[index].updatedAt = new Date().toISOString(); // 업데이트 시간 추가
			} else {
				// 리스트에 없는 경우 추가 (새로운 커스텀 코드를 업데이트한 경우 등)
				list.push({code: fullRedirectPath, url: urlToStore, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()});
			}
		} else { // operationType === 'create'
			list.push({code: fullRedirectPath, url: urlToStore, createdAt: new Date().toISOString()});
		}

		await env.RES302_KV.put(CODE_KEY, JSON.stringify(list));
		
		const status = operationType === 'update' ? 200 : 201;
		const message = operationType === 'update' ? 'URL이 업데이트되었습니다.' : '단축 URL이 생성되었습니다.';
		
		const responsePayload = {
			ok: true,
			code: fullRedirectPath,
			message
		};


		responsePayload.shortUrl = `https://${serviceType}.ggm.kr/${fullRedirectPath}`;

		return jsonResponse(responsePayload, status);
	}catch(e){
		console.error('handleShorten error:', e.message, e.stack); // 오류 로깅 강화
		return jsonResponse({error:'서버 오류'}, 500);
	}
}

async function handleList(env){
	const raw = await env.RES302_KV.get(CODE_KEY);
	const list = raw ? JSON.parse(raw) : [];
	return jsonResponse(list, 200);
}

// 추가: Google OAuth 콜백을 처리하고 토큰을 교환하는 함수
async function handleAuthCallback(request, env) {
	try {
		const { code, code_verifier, redirect_uri } = await request.json();
		if (!code || !code_verifier || !redirect_uri) {
			return jsonResponse({ error: '필수 파라미터가 누락되었습니다.' }, 400);
		}

		// 환경 변수에서 Google OAuth 클라이언트 정보 가져오기
		const GOOGLE_CLIENT_ID = env.GOOGLE_CLIENT_ID;
		const GOOGLE_SECRET = env.GOOGLE_SECRET;

		if (!GOOGLE_CLIENT_ID || !GOOGLE_SECRET) {
			return jsonResponse({ error: '서버에 OAuth 환경 변수가 설정되지 않았습니다.' }, 500);
		}

		const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code: code,
			client_id: GOOGLE_CLIENT_ID,
			client_secret: GOOGLE_SECRET,
			redirect_uri: redirect_uri,
			code_verifier: code_verifier,
		});

		const res = await fetch(TOKEN_ENDPOINT, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString(),
		});

		if (!res.ok) {
			const errorText = await res.text();
			console.error('Google Token Exchange Error:', errorText);
			return jsonResponse({ error: 'Google 인증 토큰 교환에 실패했습니다.', details: errorText }, 400);
		}

		const tokens = await res.json();
		let profile = {};

		// id_token에서 프로필 정보 디코딩
		if (tokens.id_token) {
			const idp = tokens.id_token.split('.');
			if (idp[1]) {
				try {
					const payload = JSON.parse(atob(idp[1].replace(/-/g, '+').replace(/_/g, '/')));
					profile = {
						sub: payload.sub, // Google 고유 사용자 ID
						name: payload.name,
						email: payload.email,
						picture: payload.picture,
					};
				} catch (e) {
					console.error('ID Token decoding failed:', e);
				}
			}
		}

		// 추가: 사용자 정보 및 API 키 관리
		if (!profile.sub) {
			return jsonResponse({ error: 'Google 프로필 ID(sub)를 가져올 수 없습니다.' }, 500);
		}

		let uniqueUserId;
		let userData;
		let apiKey;

		// Google sub ID로 기존 사용자 조회
		const existingUniqueUserId = await env.GOOGLE_SUB_TO_USER_ID_KV.get(profile.sub);

		if (existingUniqueUserId) {
			// 기존 사용자: uniqueUserId 사용
			uniqueUserId = existingUniqueUserId;
			const userKey = `user:${uniqueUserId}`;
			userData = await env.USER_KV.get(userKey, { type: 'json' });

			if (userData) {
				// 기존 사용자 데이터가 있으면 API 키 재사용 및 마지막 로그인 시간 업데이트
				apiKey = userData.apiKey;
				userData.lastLoginAt = new Date().toISOString();
			} else {
				// 매핑은 있는데 USER_KV에 데이터가 없는 경우 (비정상 상태, 새로 생성)
				console.warn(`User mapping exists for sub ${profile.sub} but no user data in USER_KV. Recreating.`);
				apiKey = makeApiKey();
				userData = {
					uniqueUserId: uniqueUserId,
					sub: profile.sub,
					email: profile.email,
					name: profile.name,
					picture: profile.picture,
					apiKey: apiKey,
					createdAt: new Date().toISOString(),
					lastLoginAt: new Date().toISOString(),
				};
			}
		} else {
			// 새 사용자: uniqueUserId 생성 및 정보 저장
			uniqueUserId = makeUniqueId(); // 12자리 고유 ID 생성
			apiKey = makeApiKey(); // 새 API 키 생성
			userData = {
				uniqueUserId: uniqueUserId,
				sub: profile.sub,
				email: profile.email,
				name: profile.name,
				picture: profile.picture,
				apiKey: apiKey,
				createdAt: new Date().toISOString(),
				lastLoginAt: new Date().toISOString(),
			};
			// Google sub ID -> uniqueUserId 매핑 저장
			await env.GOOGLE_SUB_TO_USER_ID_KV.put(profile.sub, uniqueUserId);
		}

		// USER_KV에 사용자 데이터 저장/업데이트
		await env.USER_KV.put(`user:${uniqueUserId}`, JSON.stringify(userData));
		// API 키 -> uniqueUserId 매핑 저장
		await env.API_KEY_TO_SUB_KV.put(apiKey, uniqueUserId);

		// 클라이언트에 토큰, 프로필 정보 (uniqueUserId 포함), API 키 반환
		// 변경: uniqueUserId를 profile 객체 안에 중첩시키는 대신, 최상위 속성으로 직접 반환
		return jsonResponse({ tokens, profile: { ...profile, uniqueUserId }, apiKey, uniqueUserId }, 200);

	} catch (e) {
		// 변경: 오류 로깅 강화
		console.error('Auth Callback Error:', e.message, e.stack, e);
		return jsonResponse({ error: '인증 처리 중 서버 오류가 발생했습니다.' }, 500);
	}
}


export async function handleRequest(request, env){

	// OPTIONS preflight 처리 추가
	if(request.method === 'OPTIONS'){
		return new Response(null, {status:204, headers: corsHeaders()});
	}

	const url = new URL(request.url);
	const pathname = url.pathname;

	// 추가: POST /api/member 라우트
	if (request.method === 'POST' && pathname === '/api/member') {
		return handleAuthCallback(request, env);
	}

	// API: POST /api/shorten
	if(request.method === 'POST' && pathname === '/api/shorten'){
		return handleShorten(request, env);
	}
	// API: GET /api/list
	// if(request.method === 'GET' && pathname === '/api/list'){
	// 	return handleList(env);
	// }
	// 리다이렉트: GET /{code} 또는 /{uniqueUserId}/{code}
	if(request.method === 'GET' && pathname.length > 1){
		const fullPath = pathname.slice(1); // 예: "user123abcde/my/custom/code" 또는 "abc123"
		const pathSegments = fullPath.split('/');
		let targetCode = null; // KV에서 조회할 최종 키

		// 변경: 첫 번째 세그먼트가 uniqueUserId (영숫자)처럼 보이는지 확인하는 휴리스틱
		// makeUniqueId 함수는 12자리 ID를 생성하지만, 기존 ID나 수동 입력 ID를 위해 길이에 대한 엄격한 검사를 완화합니다.
		// 대신, 첫 번째 세그먼트가 영숫자로만 구성되어 있고, 경로 세그먼트가 2개 이상인 경우를 uniqueUserId 패턴으로 간주합니다.
		const isFirstSegmentPotentiallyUniqueUserId = pathSegments.length >= 2 && /^[a-z0-9]+$/i.test(pathSegments[0]);

		if (isFirstSegmentPotentiallyUniqueUserId) {
			// /{uniqueUserId}/{alias_with_slashes} 패턴으로 간주
			// KV 키는 전체 경로 (예: "user123abcde/my/custom/code")
			targetCode = fullPath;
		} else if (pathSegments.length === 1) {
			// /{code} 패턴 (무작위 코드)으로 간주
			targetCode = fullPath;
		}
		// 그 외의 경우 (예: pathSegments.length > 1 이지만 첫 세그먼트가 uniqueUserId 패턴이 아닌 경우)
		// 유효하지 않은 경로로 간주하여 404로 처리됩니다.

		if (targetCode) {
			const target = await env.RES302_KV.get(targetCode);
			if(target){
				return new Response(null, {status:302, headers: Object.assign({Location: target}, corsHeaders())});
			}
		}
		return new Response('Not found', {status:404, headers: corsHeaders()});
	}
	// 기타
	return new Response('Not found', {status:404, headers: corsHeaders()});
}

export default {
	fetch: handleRequest
};
