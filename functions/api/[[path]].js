// functions/api/[[path]].js

export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const method = request.method;
    
    // 获取动态路由的具体动作 (比如请求 /api/list，action 就是 "list")
    const action = params.path ? params.path[0] : ''; 

    // 预先读取 KV 里的节点列表，方便后续各个接口直接使用
    let list = await env.KUI_KV.get("nodes", { type: "json" }) || [];

    try {
        // --- 1. 获取节点列表 ---
        if (action === "list" && method === "GET") {
            return Response.json(list);
        }

        // --- 2. 添加节点 ---
        if (action === "add" && method === "POST") {
            const newNode = await request.json();
            list.push(newNode);
            await env.KUI_KV.put("nodes", JSON.stringify(list));
            return Response.json({ success: true });
        }

        // --- 3. 删除节点 ---
        if (action === "del" && method === "DELETE") {
            const index = parseInt(url.searchParams.get("index"));
            if (!isNaN(index) && index >= 0 && index < list.length) {
                list.splice(index, 1);
                await env.KUI_KV.put("nodes", JSON.stringify(list));
            }
            return Response.json({ success: true });
        }

        // --- 4. 供 VPS 端脚本拉取配置 ---
        if (action === "config" && method === "GET") {
            const ip = url.searchParams.get("ip");
            const myNode = list.find(n => n.vps_ip === ip);
            return Response.json(myNode || { error: "未找到该 IP 的配置" });
        }

        // 如果路径不匹配
        return new Response("Not Found API Route", { status: 404 });
        
    } catch (err) {
        // 异常捕获，方便在本地调试或抓包排错
        return Response.json({ error: err.message }, { status: 500 });
    }
}
