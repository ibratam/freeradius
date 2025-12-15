const express = require('express');
const { RouterOSAPI } = require('node-routeros');
const cors = require('cors');
const axios = require('axios');
const radius = require('radius');
const dgram = require("dgram");
const app = express();
const PORT = process.env.PORT || 3000;
const RADIUS_PORT = 3799;
const UISP_URL=process.env.UISP_URL;
const UISP_API_TOKEN=process.env.UISP_API_TOKEN;
const Docker = require('dockerode');
const docker = new Docker({ socketPath: '/var/run/docker.sock' });


// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// MikroTik connection configuration
const mikrotikConfig = {
    host: process.env.MIKROTIK_HOST ,
    user: process.env.MIKROTIK_USER ,
    password: process.env.MIKROTIK_PASSWORD ,
    port: process.env.MIKROTIK_PORT ,
    timeout: 5000
};
let conn = new RouterOSAPI(

    mikrotikConfig);
// Create RouterOS API connection
async function connectToMikroTik() {


    try {
        await conn.connect();
        //console.log('Connected to MikroTik router');
        return conn;
    } catch (error) {
        console.error('Failed to connect to MikroTik:', error.message);
        throw error;
    }
}

// Format bytes to human readable format
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Calculate bandwidth in bps
function calculateBandwidth(current, previous, timeDiff) {
    if (!previous || timeDiff <= 0) return 0;
    return Math.round(((current - previous) * 8) / (timeDiff / 1000)); // Convert to bits per second
}

// Format bandwidth to human readable format
function formatBandwidth(bps) {
    if (bps === 0) return '0 bps';
    const k = 1000;
    const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    const i = Math.floor(Math.log(bps) / Math.log(k));
    return parseFloat((bps / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
async function allaps(){
    let ss;
    await axios.get(`${UISP_URL}/nms/api/v2.1/devices`, {
        params: {
            role:'ap'
        },
        headers: {
            'accept': 'application/json',
            'x-auth-token': UISP_API_TOKEN
        },
        httpsAgent: new (require('https').Agent)({
            rejectUnauthorized: false // Allow self-signed certs
        })
    }).then(response => {
        //console.log(response.data);
        ss= response.data;
    }).catch(error => {
        console.error('Error:', error.message);
    });
    return ss;

}
async function allstations(){
    let ss;
    await axios.get(`${UISP_URL}/nms/api/v2.1/devices`, {
        params: {
            role:'station'
        },
        headers: {
            'accept': 'application/json',
            'x-auth-token': UISP_API_TOKEN
        },
        httpsAgent: new (require('https').Agent)({
            rejectUnauthorized: false // Allow self-signed certs
        })
    }).then(response => {
        //console.log(response.data);
        ss= response.data;
    }).catch(error => {
        console.error('Error:', error.message);
    });
    return ss;

}

async function allswitches(){
    let ss;
    await axios.get(`${UISP_URL}/nms/api/v2.1/devices`, {
        params: {
            role:'switch'
        },
        headers: {
            'accept': 'application/json',
            'x-auth-token': UISP_API_TOKEN
        },
        httpsAgent: new (require('https').Agent)({
            rejectUnauthorized: false // Allow self-signed certs
        })
    }).then(response => {
        //console.log(response.data);
        ss= response.data;
    }).catch(error => {
        console.error('Error:', error.message);
    });
    return ss;

}

// Store previous stats for bandwidth calculation
let previousStats = new Map();
let lastUpdateTime = Date.now();
// Get PPPoE interfaces traffic
async function getPPPoETraffic() {
    let conn;
    try {
        conn = await connectToMikroTik();

        // Get all PPPoE server interfaces
        const pppoeInterfaces = await conn.write('/ppp/active/print');

        const currentTime = Date.now();
        const timeDiff = currentTime - lastUpdateTime;
        lastUpdateTime=currentTime;
        const trafficData = [];

        for (const iface of pppoeInterfaces) {
            try {
                // Get interface statistics
                const stats = await conn.write('/interface/print', [
                    "?name=<pppoe-"+ iface.name+">" ,
                    '=stats'
                ]);

                if (stats && stats.length > 0) {
                    const stat = stats[0];
                    const interfaceName = iface.name;
                    const previousStat = previousStats.get(interfaceName);

                    const rxBytes = parseInt(stat['rx-byte']) || 0;
                    const txBytes = parseInt(stat['tx-byte']) || 0;
                    const rxPackets = parseInt(stat['rx-packet']) || 0;
                    const txPackets = parseInt(stat['tx-packet']) || 0;

                    // Calculate bandwidth
                    const rxBandwidth = previousStat ?
                        calculateBandwidth(rxBytes, previousStat.rxBytes, timeDiff) : 0;
                    const txBandwidth = previousStat ?
                        calculateBandwidth(txBytes, previousStat.txBytes, timeDiff) : 0;

                    const interfaceData = {
                        interface: interfaceName,
                        user: iface.name.replace('<pppoe-', '').replace('>', ''),
                        address: iface.address || 'N/A',
                        uptime: iface.uptime || '0s',
                        callerID: iface['caller-id'] || 'N/A',
                        service: iface.service || 'N/A',
                        traffic: {
                            rx: {
                                bytes: rxBytes,
                                bytesFormatted: formatBytes(rxBytes),
                                packets: rxPackets,
                                bandwidth: rxBandwidth,
                                bandwidthFormatted: formatBandwidth(rxBandwidth)
                            },
                            tx: {
                                bytes: txBytes,
                                bytesFormatted: formatBytes(txBytes),
                                packets: txPackets,
                                bandwidth: txBandwidth,
                                bandwidthFormatted: formatBandwidth(txBandwidth)
                            },
                            total: {
                                bytes: rxBytes + txBytes,
                                bytesFormatted: formatBytes(rxBytes + txBytes),
                                packets: rxPackets + txPackets,
                                bandwidth: rxBandwidth + txBandwidth,
                                bandwidthFormatted: formatBandwidth(rxBandwidth + txBandwidth)
                            }
                        },
                        timestamp: currentTime
                    };

                    // Store current stats for next calculation
                    previousStats.set(interfaceName, {
                        rxBytes,
                        txBytes,
                        timestamp: currentTime
                    });

                    trafficData.push(interfaceData);
                }
            } catch (error) {
                console.error(`Error getting stats for interface ${iface.name}:`, error.message);
            }
        }


        return trafficData;

    } catch (error) {
        console.error('Error fetching PPPoE traffic:', error.message);
        throw error;
    } finally {
        if (conn) {
            try {
                await conn.close();
            } catch (error) {
                console.error('Error closing connection:', error.message);
            }
        }
    }
}

async function getSearchResults(query,limit) {
    let ss;
    await axios.get(`${UISP_URL}/nms/api/v2.1/nms/search`, {
        params: {
            query: query,
            count: limit,
            page: 1
        },
        headers: {
            'accept': 'application/json',
            'x-auth-token': UISP_API_TOKEN
        },
        httpsAgent: new (require('https').Agent)({
            rejectUnauthorized: false // Allow self-signed certs
        })
    }).then(response => {
        // console.log(response.data);
        ss= response.data;
    }).catch(error => {
        console.error('Error:', error.message);
    });
    return ss;

}
function formatUptimeDetailed(seconds) {
    const days = Math.floor(seconds / (24 * 3600));
    const hours = Math.floor((seconds % (24 * 3600)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    const parts = [];

    if (days > 0) {
        parts.push(`${days} day${days !== 1 ? 's' : ''}`);
    }
    if (hours > 0) {
        parts.push(`${hours} hour${hours !== 1 ? 's' : ''}`);
    }
    if (minutes > 0) {
        parts.push(`${minutes} minute${minutes !== 1 ? 's' : ''}`);
    }
    seconds=seconds%60;
    parts.push(`${seconds} seconds`);
    return parts.join(', ') || '0 seconds' ;
}

async function devices_by_type(type){
    let ss;
    await axios.get(`${UISP_URL}/nms/api/v2.1/devices`, {
        params: {
            role:type
        },
        headers: {
            'accept': 'application/json',
            'x-auth-token': UISP_API_TOKEN
        },
        httpsAgent: new (require('https').Agent)({
            rejectUnauthorized: false // Allow self-signed certs
        })
    }).then(response => {
        //console.log(response.data);
        ss= response.data;
    }).catch(error => {
        console.error('Error:', error.message);
    });
    return ss;

}

// API Routes

// Get all PPPoE interfaces traffic
app.get('/api/pppoe/traffic', async (req, res) => {
    try {
        const traffic = await getPPPoETraffic();
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            count: traffic.length,
            data: traffic
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});
app.get('/api/uisp/devices/:type',async (req, res) => {
    try {
        const dt = await devices_by_type(req.params.type);
//         console.log(dt);
        // Iterate through all results and transform each one
        const results = dt.map(item => ({
            ethSpeed:item.overview.mainInterfaceSpeed.availableSpeed,
            id: item.identification.id,
            name: item.identification.name,
            site: item.identification.site.name,
            mac: item.identification.mac,
            ip: item.ipAddress?.split('/')[0] || item.ipAddress,
            status: item.overview.status.toUpperCase(),
            model :item.identification.modelName,
            cpu: item.overview.cpu + "%",
            uptime: formatUptimeDetailed(item.overview.uptime),
        }));

        res.json({
            results
            //  dt
        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({
            error: 'Failed to fetch switches data',
            details: error.message
        });
    }
});

app.get('/api/uisp/login-link/', async (req, res) => {
    const mac = req.query.mac;
    const ip = req.query.ip;
    if (!mac || !ip) {
        return res.status(400).json({ error: 'MAC address and IP are required' });
    }

    try {
        const requestUrl = `${UISP_URL}/nms/api/v2.1/devices/login?mac=${encodeURIComponent(mac)}&ip=${encodeURIComponent(ip)}`;

        const response = await axios.get(requestUrl, {
            headers: {
                'accept': 'application/json',
                'x-auth-token': UISP_API_TOKEN
            }
        });

        const ticketId = response.data?.ticket?.id;

        if (!ticketId) {
            return res.status(500).json({ error: 'No ticket returned from UISP' });
        }

        const directUrl = `https://${ip}/#ticketid=${ticketId}`;

        res.redirect(directUrl);


    } catch (err) {
        res.status(500).json({
            error: 'Failed to retrieve login link',
            details: err.response?.data || err.message
        });
    }
});
// Get specific PPPoE interface traffic
app.get('/api/pppoe/traffic/:interface', async (req, res) => {
    try {
        const interfaceName = req.params.interface;
        const allTraffic = await getPPPoETraffic();
        const specificTraffic = allTraffic.find(t =>
            t.interface === interfaceName || t.user === interfaceName
        );

        if (!specificTraffic) {
            return res.status(404).json({
                success: false,
                error: 'Interface not found',
                timestamp: new Date().toISOString()
            });
        }

        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            data: specificTraffic
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Get traffic summary
app.get('/api/pppoe/summary', async (req, res) => {
    try {
        const traffic = await getPPPoETraffic();

        const summary = traffic.reduce((acc, curr) => {
            acc.totalRxBytes += curr.traffic.rx.bytes;
            acc.totalTxBytes += curr.traffic.tx.bytes;
            acc.totalRxBandwidth += curr.traffic.rx.bandwidth;
            acc.totalTxBandwidth += curr.traffic.tx.bandwidth;
            acc.totalPackets += curr.traffic.total.packets;
            return acc;
        }, {
            totalInterfaces: traffic.length,
            totalRxBytes: 0,
            totalTxBytes: 0,
            totalRxBandwidth: 0,
            totalTxBandwidth: 0,
            totalPackets: 0
        });

        summary.totalBytes = summary.totalRxBytes + summary.totalTxBytes;
        summary.totalBandwidth = summary.totalRxBandwidth + summary.totalTxBandwidth;
        summary.totalBytesFormatted = formatBytes(summary.totalBytes);
        summary.totalBandwidthFormatted = formatBandwidth(summary.totalBandwidth);

        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            summary
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        const conn = await connectToMikroTik();
        await conn.close();
        res.json({
            success: true,
            message: 'API and MikroTik connection healthy',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Cannot connect to MikroTik router',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});
app.post("/api/pppoe/active", async (req, res) => {
    console.log(req.body);
    try {
        let con=new RouterOSAPI({
            host: req.body.ip_address || '192.168.48.44',
            user: req.body.user ||  'api',
            password: req.body.password ||  '123456789',
            port: req.body.port|| 8728,
            timeout: 5000
        } );


        await con.connect();
        const result = await con.write("/ppp/active/print");
        console.log(result);
        res.json(result);  // send JSON array of active PPPoE sessions
        await con.close();
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: err.message });
    }
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'go tech API ',
        endpoints: {
            'GET /api/pppoe/traffic': 'Get all PPPoE interfaces traffic',
            'GET /api/pppoe/traffic/:interface': 'Get specific interface traffic',
            'GET /api/pppoe/summary': 'Get traffic summary',
            'POST /api/pppoe/disconnect':'disconnect user connection ',
            'GET /api/uisp/:query':'search uisp device with query returns 1 opject',
            'GET /api/uisp/aps':'return all access points in uisp' ,
            'GET /api/health': 'Health check',



        }
    });
});
app.get('/api/uisp/stations', async (req, res) => {
    try {
        const dt = await allstations();
        // console.log(dt[0]);
        // Iterate through all results and transform each one
        const results = dt.map(item => ({
            ethSpeed:item.overview.mainInterfaceSpeed.availableSpeed,
            id: item.identification.id,
            name: item.identification.name,
            site: item.identification.site.name,
            mac: item.identification.mac,
            ip: item.ipAddress?.split('/')[0] || item.ipAddress,
            status: item.overview.status.toUpperCase(),
            model :item.identification.model,
            cpu: item.overview.cpu + "%",
            uptime: formatUptimeDetailed(item.overview.uptime),
            ssid: item.attributes.ssid,
            ap_name: item.attributes.apDevice?.name,
        }));

        res.json({
            results

        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({
            error: 'Failed to fetch access point data',
            details: error.message
        });
    }
});
app.get('/api/uisp/switches',async (req, res) => {
    try {
        const dt = await allswitches();
        console.log(dt);
        // Iterate through all results and transform each one
        const results = dt.map(item => ({
            ethSpeed:item.overview.mainInterfaceSpeed.availableSpeed,
            id: item.identification.id,
            name: item.identification.name,
            site: item.identification.site.name,
            mac: item.identification.mac,
            ip: item.ipAddress?.split('/')[0] || item.ipAddress,
            status: item.overview.status.toUpperCase(),
            model :item.identification.modelName,
            cpu: item.overview.cpu + "%",
            uptime: formatUptimeDetailed(item.overview.uptime),
        }));

        res.json({
            results
        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({
            error: 'Failed to fetch switches data',
            details: error.message
        });
    }
});
app.get('/api/uisp/aps', async (req, res) => {
    try {
        const dt = await allaps();
        // console.log(dt);
        // Iterate through all results and transform each one
        const results = dt.map(item => ({
            ethSpeed:item.overview.mainInterfaceSpeed.availableSpeed,
            id: item.identification.id,
            name: item.identification.name,
            site: item.identification.site.name,
            clientsNum: item.overview.stationsCount,
            mac: item.identification.mac,
            ip: item.ipAddress?.split('/')[0] || item.ipAddress,
            status: item.overview.status.toUpperCase(),
            model :item.identification.model,
            cpu: item.overview.cpu + "%",
            uptime: formatUptimeDetailed(item.overview.uptime),
            ssid: item.attributes.ssid,
        }));

        res.json({
            results
        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({
            error: 'Failed to fetch access point data',
            details: error.message
        });
    }
});

app.get('/api/uisp/:query', async (req, res) => {
    dt = await getSearchResults(req.params.query,1);
    try {

        res.json({

            id: dt[0].data.identification.id,
            name: dt[0].data.identification.name,
            mac: dt[0].data.identification.mac,
            ip: dt[0].data.ipAddress?.split('/')[0] || dt[0].data.ipAddress,
            status:dt[0].data.overview.status?.toUpperCase(),
            ap_name: dt[0].data.attributes.apDevice.name,
            ap_model: dt[0].data.attributes.apDevice.model,
            ap_ssid: dt[0].data.attributes.ssid,
            site: dt[0].data.identification.site.name,
            signal: Math.round(dt[0].data.overview.signal) + " dBm",
            cpu:dt[0].data.overview.cpu + "%",
            uptime:formatUptimeDetailed(dt[0].data.overview.uptime),
            link_potential: Math.round((dt[0].data.overview.linkScore?.linkScore ?? 0) * 100) + "%",
            download_capacity: Math.round(dt[0].data.overview.downlinkCapacity / 1048576) + " Mb",
            upload_capacity: Math.round(dt[0].data.overview.uplinkCapacity / 1048576) + " Mb"
        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({dt})

    }

});
app.post('/api/pppoe/disconnect', (req, res) => {
    const { username, sessionId, nasIp,nasSecret, framedIp } = req.body;

    if (!username || !sessionId || !nasIp) {
        return res.status(400).json({ error: 'username, sessionId, and nasIp are required' });
    }

    const packet = {
        code: 'Disconnect-Request',
        secret: nasSecret,
        identifier: 0,
        attributes: {
            'User-Name': username,
            'Acct-Session-Id': sessionId,
            'NAS-IP-Address': nasIp
        }
    };

    if (framedIp) {
        packet.attributes['Framed-IP-Address'] = framedIp;
    }

    const encoded = radius.encode(packet);
    const client = dgram.createSocket('udp4');

    client.send(encoded, 0, encoded.length, RADIUS_PORT, nasIp, (err) => {
        client.close();
        if (err) {
            console.error('Error sending CoA:', err);
            return res.status(500).json({ error: 'Failed to send CoA packet' });
        }
        res.json({ message: 'Disconnect-Request sent successfully' });
    });
});


// Endpoint to check FreeRADIUS status
app.get('/api/container/:name/status', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.name);
        const info = await container.inspect();

        res.json({
            name: info.Name.replace('/', ''),
            status: info.State.Status,
            running: info.State.Running,
            health: info.State.Health?.Status || 'N/A',
            started_at: info.State.StartedAt,
            finished_at: info.State.FinishedAt,
            restart_count: info.RestartCount
        });
    } catch (error) {
        if (error.statusCode === 404) {
            res.status(404).json({ error: 'Container not found' });
        } else {
            res.status(500).json({ error: error.message });
        }
    }
});

// Quick health check endpoint
app.get('/api/freeradius/health', async (req, res) => {
    try {
        const container = docker.getContainer('freeradius');
        const info = await container.inspect();

        res.json({
            healthy: info.State.Running,
            status: info.State.Status
        });
    } catch (error) {
        res.status(500).json({
            healthy: false,
            error: error.message
        });
    }
});

// List all containers
app.get('/api/containers', async (req, res) => {
    try {
        const containers = await docker.listContainers({ all: true });
        res.json(containers.map(c => ({
            id: c.Id,
            name: c.Names[0].replace('/', ''),
            status: c.State,
            image: c.Image
        })));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/container/:name/restart', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.name);

        // Check if container exists
        await container.inspect();

        // Restart the container
        await container.restart();

        // Wait a bit and get new status
        setTimeout(async () => {
            const info = await container.inspect();
            res.json({
                success: true,
                message: `Container ${req.params.name} restarted successfully`,
                status: info.State.Status,
                running: info.State.Running,
                restarted_at: new Date().toISOString()
            });
        }, 2000);

    } catch (error) {
        if (error.statusCode === 404) {
            res.status(404).json({
                success: false,
                error: 'Container not found'
            });
        } else {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }
});

// Stop a container
app.post('/api/container/:name/stop', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.name);
        await container.stop();
        res.json({
            success: true,
            message: `Container ${req.params.name} stopped successfully`
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Start a container
app.post('/api/container/:name/start', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.name);
        await container.start();
        res.json({
            success: true,
            message: `Container ${req.params.name} started successfully`
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Get container logs (useful for debugging)
app.get('/api/container/:name/logs', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.name);
        const logs = await container.logs({
            stdout: true,
            stderr: true,
            tail: 100 // Last 100 lines
        });

        res.json({
            success: true,
            logs: logs.toString('utf8')
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});
// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        timestamp: new Date().toISOString()
    });
});


// Start server
app.listen(PORT, () => {
    console.log(`MikroTik PPPoE Traffic Monitor API running on port ${PORT}`);
    console.log('\nAvailable endpoints:');
    console.log(`  GET http://localhost:${PORT}/api/pppoe/traffic`);
    console.log(`  GET http://localhost:${PORT}/api/pppoe/traffic/:interface`);
    console.log(`  GET http://localhost:${PORT}/api/pppoe/summary`);
    console.log(`  POST http://localhost:${PORT}/api/pppoe/disconnect`);
    console.log(`  GET http://localhost:${PORT}/api/uisp/:query`);
    console.log(`  GET http://localhost:${PORT}/api/uisp/aps`);
    console.log(`  GET http://localhost:${PORT}/api/health`);


});

module.exports = app;