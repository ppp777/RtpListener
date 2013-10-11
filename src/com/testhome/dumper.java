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

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class Dumper extends Thread {

    public static volatile Boolean stop = false;
    JTextPane jTextPane;
    final StringBuilder errbuf = new StringBuilder();

    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs

    private int numdevice = 0;
    private int timeout = 1; // 10 * 1000;           // 10 seconds in millis

    Dumper(int numdevice, int timeout, List<PcapIf> alldevs, JTextPane jTextPane) {
        super();
        this.jTextPane =jTextPane;
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
        JPacketHandler jPacketHandler = new JPH1(jTextPane);
        while(!stop){
            pcap.loop(1, jPacketHandler, errbuf);
        }
        jTextPane.setText(jTextPane.getText() + "\n STOPPED !!! ");
        jTextPane.setCaretPosition(jTextPane.getDocument().getLength());

        pcap.close();
    }

}
