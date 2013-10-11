package com.testhome;

import org.jnetpcap.*;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Rtp;
import org.jnetpcap.protocol.voip.Sip;

import java.util.ArrayList;
import java.util.List;

public class Dumper extends Thread {

    public volatile Boolean stop = false;

    final StringBuilder errbuf = new StringBuilder();

    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs

    private int numdevice = 0;
    private int timeout = 1; // 10 * 1000;           // 10 seconds in millis

    Dumper(int numdevice, int timeout, List<PcapIf> alldevs) {
        super();
        this.numdevice = numdevice;
        this.timeout = timeout;
        this.alldevs = alldevs;
    }

    public void run() {
        System.out.println(numdevice);
        PcapIf device = alldevs.get(numdevice); // We know we have atleast 1 device

        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        //int timeout = ;// 10 * 1000;           // 10 seconds in millis

        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.println(errbuf); // Error is stored in errbuf if any
            return;
        }

        pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
            final Tcp tcp = new Tcp();
            final Ip4 ipv4 = new Ip4();
            final Udp udp1 = new Udp();
            final Sip sip1 = new Sip();
            final Http http = new Http();
            final Rtp rtp1 = new Rtp();

            public void nextPacket(JPacket packet, StringBuilder errbuf) {
                String source = "";
                String destination = "";
/*
                packet.getHeader(ipv4);
                if (!(ipv4.source()).equals(null)){
                    source = FormatUtils.ip(ipv4.source());
                }
                if  (!(ipv4.destination()).equals(null)){
                    destination = FormatUtils.ip(ipv4.destination());
                }

                System.out.println("From " + source + " To " + destination);
*/
                if (packet.hasHeader(Rtp.ID)) {
                    packet.getHeader(rtp1);
                    System.out.printf("rtp1.csrcLength() = " + rtp1.csrcLength());
                    System.out.printf("rtp1.csrc() = " + rtp1.csrc());
                    System.out.printf("rtp1.ssrc()" + rtp1.ssrc());
                }

/*
                if (packet.hasHeader(Tcp.ID)) {
                    packet.getHeader(tcp);
                    System.out.printf("tcp.dst_port=%d%n", tcp.destination());
                    System.out.printf("tcp.src_port=%d%n", tcp.source());
                    System.out.printf("tcp.ack=%x%n", tcp.ack());
                }
                if (packet.hasHeader(Udp.ID)) {
                    packet.getHeader(udp1);
                    System.out.printf("udp.dst_port=%d%n", udp1.destination());
                    System.out.printf("udp.src_port=%d%n", udp1.source());
                }
*/
                System.out.printf("frame #%d%n", packet.getFrameNumber());
                if (stop) {
                    System.out.println("Interrupted ! ");
                    return;
                }
            }
        }, errbuf);

        pcap.close();
    }

}
