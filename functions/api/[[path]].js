// functions/api/[[path]].js

export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 

    // --- 1. 安全验证设置 ---
    // 默认密码是 123456，建议你在 Pages 设置里添加环境变量 ADMIN_PASSWORD 来修改
    const expectedPassword = env.ADMIN_PASSWORD || "123456"; 
    
    // VPS 专属拉取接口，免密码验证（依靠 IP 鉴权）
    if (action === "config" && method === "GET") {
        const ip = url.searchParams.get("ip");
        let list = await env.KUI_KV.get("nodes", { type: "json" }) || [];
        const myNode = list.find(n => n.vps_ip === ip);
        return Response.json(myNode || { error: "未找到该 IP 的配置" });
    }

    // 登录校验接口
    if (action === "login" && method === "POST") {
        const data = await request.json();
        if (data.password === expectedPassword) {
            return Response.json({ success: true });
        } else {
            return Response.json({ error: "Unauthorized" }, { status: 401 });
        }
    }

    // 其他管理接口，进行 Token 拦截
    const authHeader = request.headers.get("Authorization");
    if (authHeader !== expectedPassword) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    // --- 2. 面板增删改查逻辑 ---
    let list = await env.KUI_KV.get("nodes", { type: "json" }) || [];

    try {
        if (action === "list" && method === "GET") {
            return Response.json(list);
        }

        if (action === "add" && method === "POST") {
            const newNode = await request.json();
            list.push(newNode);
            await env.KUI_KV.put("nodes", JSON.stringify(list));
            return Response.json({ success: true });
        }

        if (action === "del" && method === "DELETE") {
            const index = parseInt(url.searchParams.get("index"));
            if (!isNaN(index) && index >= 0 && index < list.length) {
                list.splice(index, 1);
                await env.KUI_KV.put("nodes", JSON.stringify(list));
            }
            return Response.json({ success: true });
        }

        return new Response("Not Found API Route", { status: 404 });
        
    } catch (err) {
        return Response.json({ error: err.message }, { status: 500 });
    }
}
