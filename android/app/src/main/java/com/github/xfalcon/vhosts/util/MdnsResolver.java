package com.github.xfalcon.vhosts.util;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.util.Log;

import java.io.IOException;
import java.net.*;

public class MdnsResolver {

    public static String ZwiftAddress = "127.0.0.1";

    private static final String TAG = "MdnsResolver";
    private static final String MDNS_GROUP = "224.0.0.251";
    private static final int MDNS_PORT = 5353;

    /**
     * 查询 .local 主机名的 IP
     *
     * @param context  Android 上下文，用于 MulticastLock
     * @param hostname 需要解析的主机名，例如 "zwift.local"
     * @return InetAddress 或 null
     */
    public static InetAddress resolve(final Context context, String hostname) {
        MulticastSocket socket = null;
        WifiManager.MulticastLock lock = null;

        try {
            // 获取 MulticastLock
            WifiManager wifi = (WifiManager) context.getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            lock = wifi.createMulticastLock("mdnsLock");
            lock.setReferenceCounted(true);
            lock.acquire();

            // 创建 MulticastSocket 并加入组播
            socket = new MulticastSocket(MDNS_PORT);
            socket.setSoTimeout(2000);
            InetAddress group = InetAddress.getByName(MDNS_GROUP);
            socket.joinGroup(group);

            // 发送 mDNS 查询
            byte[] query = buildQuery(hostname);
            DatagramPacket packet = new DatagramPacket(query, query.length, group, MDNS_PORT);
            socket.send(packet);

            // 循环接收响应
            for (int attempt = 0; attempt < 5; attempt++) {
                try {
                    byte[] buf = new byte[512];
                    DatagramPacket response = new DatagramPacket(buf, buf.length);
                    socket.receive(response);

                    InetAddress addr = parseARecord(response.getData(), response.getLength());
                    if (addr != null) return addr;

                } catch (SocketTimeoutException ignored) {
                    // 等待下一次响应
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "mDNS 查询失败", e);
        } finally {
            if (socket != null) {
                try {
                    InetAddress group = InetAddress.getByName(MDNS_GROUP);
                    socket.leaveGroup(group);
                    socket.close();
                } catch (IOException ignored) {}
            }
            if (lock != null && lock.isHeld()) lock.release();
        }

        return null;
    }

    // 构建最简 mDNS A 记录查询报文
    private static byte[] buildQuery(String hostname) throws IOException {
        if (!hostname.endsWith(".local")) {
            hostname += ".local";
        }
        String[] labels = hostname.split("\\.");
        int length = 12; // Header
        for (String label : labels) length += label.length() + 1;
        length += 5; // null + TYPE(2) + CLASS(2)

        byte[] data = new byte[length];
        // Header
        data[0] = 0; data[1] = 0;   // ID
        data[2] = 0; data[3] = 0;   // Flags
        data[4] = 0; data[5] = 1;   // QDCOUNT=1
        data[6] = 0; data[7] = 0;   // ANCOUNT
        data[8] = 0; data[9] = 0;   // NSCOUNT
        data[10] = 0; data[11] = 0; // ARCOUNT

        int pos = 12;
        for (String label : labels) {
            data[pos++] = (byte) label.length();
            for (char c : label.toCharArray()) data[pos++] = (byte) c;
        }
        data[pos++] = 0; // 名称结束
        data[pos++] = 0; data[pos++] = 1; // TYPE=A
        data[pos++] = 0; data[pos++] = 1; // CLASS=IN

        return data;
    }

    // 解析 A 记录，支持压缩指针
    private static InetAddress parseARecord(byte[] data, int length) throws UnknownHostException {
        if (length < 12) return null;
        int qdcount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
        int ancount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
        if (ancount == 0) return null;

        int pos = 12;
        // 跳过 Query Section
        for (int i = 0; i < qdcount; i++) {
            while (pos < length && data[pos] != 0) {
                pos += (data[pos] & 0xFF) + 1;
            }
            pos += 5; // null + TYPE(2) + CLASS(2)
        }

        // 解析 Answer Section
        for (int i = 0; i < ancount && pos + 16 <= length; i++) {
            int nameByte = data[pos++] & 0xFF;
            if ((nameByte & 0xC0) == 0xC0) {
                pos++; // 压缩指针
            } else {
                while (nameByte > 0) {
                    pos += nameByte;
                    nameByte = data[pos++] & 0xFF;
                }
            }

            int type = ((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF);
            pos += 2; // CLASS
            pos += 4; // TTL
            int rdlength = ((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF);
            if (type == 1 && rdlength == 4) {
                return InetAddress.getByAddress(new byte[]{
                        data[pos], data[pos + 1], data[pos + 2], data[pos + 3]
                });
            }
            pos += rdlength;
        }

        return null;
    }
}