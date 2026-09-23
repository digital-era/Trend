<script>
(function guardAccess() {
  // ========== 配置 ==========
  // 拒绝访问后可跳转的首页（按优先级）
  var HOME_URLS = [
    'https://talktonorthstar.aivibeinvestment.com/',
    'https://aivibeinvestment.com/QuantGuardians/'
  ];
  var HOME_URL = HOME_URLS[0];   // 默认跳第一个

  var VIP_USER_TYPE  = 'vip';
  var VVIP_USER_TYPE = 'vvip';
  var SESSION_KEY    = 'qgr_trend_ok';
  var SESSION_MAX_MS = 8 * 60 * 60 * 1000;   // 会话 8 小时

  function deny(reason) {
    console.warn('[Trend] Access denied:', reason);
    try {
      document.documentElement.innerHTML =
          '<head><meta charset="UTF-8"><title>访问被拒绝</title></head>'
        + '<body style="margin:0;background:#050510;color:#EF4444;'
        + 'font-family:\'Courier New\',monospace;height:100vh;'
        + 'display:flex;flex-direction:column;justify-content:center;'
        + 'align-items:center;gap:12px;letter-spacing:1px;">'
        + '<div style="font-size:42px;">⛔</div>'
        + '<div style="font-size:16px;">访问被拒绝</div>'
        + '<div style="color:#666;font-size:13px;">' + reason + '</div>'
        + '<div style="color:#555;font-size:12px;margin-top:20px;">3 秒后返回首页...</div>'
        + '</body>';
    } catch (e) {}
    try { window.stop(); } catch (e) {}
    setTimeout(function () { window.location.replace(HOME_URL); }, 3000);
  }

  // ---------- 工具：解析 JWT payload ----------
  function parseJwtPayload(token) {
    var parts = token.split('.');
    if (parts.length !== 3) throw new Error('Token 格式非法');
    return JSON.parse(
      decodeURIComponent(
        atob(parts[1]).split('').map(function (c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join('')
      )
    );
  }

  // ---------- 1. 优先从 URL 参数获取 token（主站跨域带来）----------
  var params = new URLSearchParams(location.search);
  var urlToken = params.get('token');
  var ts       = params.get('ts');

  if (urlToken) {
    try {
      // 先校验再写入，避免脏数据污染
      var tmpPayload = parseJwtPayload(urlToken);
      if (!tmpPayload.exp || Date.now() > tmpPayload.exp) {
        return deny('携带的 Token 已过期');
      }
      localStorage.setItem('qgr_jwt_token', urlToken);
      console.log('[Trend] Token 已从 URL 写入 localStorage');
    } catch (e) {
      return deny('URL 携带的 Token 无效');
    }
  }

  // ---------- 2. 从 localStorage 读取最终 token ----------
  var token = localStorage.getItem('qgr_jwt_token');
  if (!token) return deny('未检测到登录凭证，请从主站进入');

  // ---------- 3. 解析并校验 ----------
  var payload;
  try {
    payload = parseJwtPayload(token);
  } catch (e) {
    localStorage.removeItem('qgr_jwt_token');
    return deny('Token 解析失败');
  }

  // 过期
  if (!payload.exp || Date.now() > payload.exp) {
    localStorage.removeItem('qgr_jwt_token');
    sessionStorage.removeItem(SESSION_KEY);
    return deny('登录已过期，请重新登录');
  }

  // VIP 校验（admin → vvip → vip）
  var username = payload.user || '';
  var isAdmin  = (username === 'admin');
  var isVVIP   = (username.indexOf(VVIP_USER_TYPE) === 0);
  var isVIP    = (username.indexOf(VIP_USER_TYPE)  === 0);
  if (!isAdmin && !isVVIP && !isVIP) {
    return deny('当前账号无 VIP 权限');
  }

  // ---------- 4. 入场券 / 会话校验 ----------
  var sessionOk = false;
  try {
    var sess = sessionStorage.getItem(SESSION_KEY);
    if (sess) {
      var age = Date.now() - parseInt(sess, 10);
      if (!isNaN(age) && age < SESSION_MAX_MS) {
        sessionOk = true;
      } else {
        sessionStorage.removeItem(SESSION_KEY);
      }
    }
  } catch (e) {}

  if (!sessionOk) {
    // 没有有效会话 → 必须带 60 秒内的 ts
    if (!ts) return deny('缺少入场券，请从主站进入');
    var ticketAge = Date.now() - parseInt(ts, 10);
    if (isNaN(ticketAge) || ticketAge > 60 * 1000) {
      return deny('入场券已过期（超过 60 秒）');
    }
    // 首次通过，写入会话标记
    try { sessionStorage.setItem(SESSION_KEY, String(Date.now())); } catch (e) {}
  }

  // ---------- 5. 立刻抹掉敏感参数（token + ts），防止泄露到历史/分享 ----------
  try {
    var proxyParam = params.get('proxy');
    var keepSearch = (proxyParam === '0' || proxyParam === '1') ? '?proxy=' + proxyParam : '';
    history.replaceState({}, '', location.pathname + keepSearch);
  } catch (e) {}

  // ---------- 6. 挂载用户信息 ----------
  window.__TRADE_AGENT_USER__ = {
    username:  username,
    level:     isAdmin ? 'admin' : (isVVIP ? 'vvip' : 'vip'),
    grantedAt: Date.now()
  };

  console.log('[Trend] Access granted:', window.__TRADE_AGENT_USER__);
})();
</script>
