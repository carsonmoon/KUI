export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 
    
    // Pages 环境变量配置的密码
    const ADMIN_PASS = env.ADMIN_PASSWORD || "admin"; 
    // D1 数据库实例绑定
    const db = env.DB; 

    // --- [免密/Agent 公开接口] ---

    // 探针上报
    if (action === "report" && method === "POST") {
        const data = await request.json(); 
        await db.prepare("UPDATE servers SET cpu = ?, mem = ?, last_report = ? WHERE ip = ?")
                .bind(data.cpu, data.mem, Date.now(), data.ip).run();
        return Response.json({ success: true });
    }

    // Agent 轮询拉取配置
    if (action === "config" && method === "GET") {
        if (request.headers.get("Authorization") !== ADMIN_PASS) return Response.json({ error: "Unauthorized" }, { status: 401 });
        const ip = url.searchParams.get("ip");
        
        const { results: machineNodes } = await db.prepare("SELECT * FROM nodes WHERE vps_ip = ?").bind(ip).all();
        
        // 智能组装链式代理所需的目标配置
        for (let node of machineNodes) {
            if (node.protocol === "dokodemo-door" && node.relay_type === "internal") {
                const targetNode = await db.prepare("SELECT * FROM nodes WHERE id = ?").bind(node.target_id).first();
                if (targetNode) {
                    node.chain_target = {
                        ip: targetNode.vps_ip,
                        port: targetNode.port,
                        protocol: targetNode.protocol,
                        uuid: targetNode.uuid,
                        sni: targetNode.sni,
                        public_key: targetNode.public_key,
                        short_id: targetNode.short_id
                    };
                }
            }
        }
        return Response.json({ success: true, configs: machineNodes });
    }

    // 登录校验
    if (action === "login" && method === "POST") {
        const data = await request.json();
        if (data.password === ADMIN_PASS) return Response.json({ success: true });
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    // --- [管理拦截接口] ---
    if (request.headers.get("Authorization") !== ADMIN_PASS) return Response.json({ error: "Unauthorized" }, { status: 401 });

    try {
        // 获取全量数据
        if (action === "data" && method === "GET") {
            const servers = (await db.prepare("SELECT * FROM servers ORDER BY last_report DESC").all()).results;
            const nodes = (await db.prepare("SELECT * FROM nodes").all()).results;
            return Response.json({ servers, nodes });
        }

        // VPS CRUD
        if (action === "vps") {
            if (method === "POST") {
                const { ip, name } = await request.json();
                await db.prepare("INSERT OR IGNORE INTO servers (ip, name) VALUES (?, ?)").bind(ip, name).run();
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                await db.prepare("DELETE FROM servers WHERE ip = ?").bind(url.searchParams.get("ip")).run();
                return Response.json({ success: true });
            }
        }

        // 节点 CRUD
        if (action === "nodes") {
            if (method === "POST") {
                const n = await request.json();
                await db.prepare(`
                    INSERT INTO nodes (id, uuid, vps_ip, protocol, port, sni, private_key, public_key, short_id, relay_type, target_ip, target_port, target_id) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `).bind(
                    n.id, n.uuid, n.vps_ip, n.protocol, n.port, 
                    n.sni || null, n.private_key || null, n.public_key || null, n.short_id || null, 
                    n.relay_type || null, n.target_ip || null, n.target_port || null, n.target_id || null
                ).run();
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                await db.prepare("DELETE FROM nodes WHERE id = ?").bind(url.searchParams.get("id")).run();
                return Response.json({ success: true });
            }
        }
        return new Response("Not Found", { status: 404 });
    } catch (err) { return Response.json({ error: err.message }, { status: 500 }); }
}
