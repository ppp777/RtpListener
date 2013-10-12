package com.testhome;

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

public class JPH1 implements JPacketHandler<StringBuilder> {

        final Tcp tcp = new Tcp();
        final Ip4 ipv4 = new Ip4();
        final Udp udp1 = new Udp();
        final Sip sip1 = new Sip();
        final Http http = new Http();
        final Rtp rtp1 = new Rtp();
        JTextPane textPane1;
    JPH1(JTextPane jTextPane){
        this.textPane1 = jTextPane;
    }
    @Override
    public void nextPacket(JPacket packet, StringBuilder errbuf) {

        String source = "";
        String destination = "";
        String printResult = "";

        try {
            packet.getHeader(ipv4);
            if (!(ipv4.source()).equals(null)){
                source = FormatUtils.ip(ipv4.source());
            }
            if  (!(ipv4.destination()).equals(null)){
                destination = FormatUtils.ip(ipv4.destination());
            }
            //textPane1.setText(textPane1.getText() + "> Source ip = " + source + ";  Destination ip = " + destination + "\n");
            printResult = "> Source ip = " + source + ";  Destination ip = " + destination + "\n";
        }
        catch (Exception e){
            printResult = printResult + "!!! Exception ip IP Addr > " + e.getCause() + "\n";
            textPane1.setText(textPane1.getText() + printResult);
            textPane1.setCaretPosition(textPane1.getDocument().getLength());
        }
        //System.out.println("From " + source + " To " + destination);

        if (packet.hasHeader(Sip.ID)) {
            packet.getHeader(sip1);
            printResult = printResult + "> sip1.getMethod().name() = " + sip1.getMethod().name() + "\n";
//            textPane1.setText(textPane1.getText() + "> rtp1.csrcLength() = " + rtp1.csrcLength() + ";  rtp1.csrc() = " + rtp1.csrc() + "; rtp1.ssrc()" + rtp1.ssrc() + "\n");
//            System.out.printf("rtp1.csrcLength() = " + rtp1.csrcLength() + ";  rtp1.csrc() = " + rtp1.csrc() + "; rtp1.ssrc()" + rtp1.ssrc());
        }

        if (packet.hasHeader(Rtp.ID)) {
            packet.getHeader(rtp1);
            printResult = printResult + "> rtp1.csrcLength() = " + rtp1.csrcLength() + ";  rtp1.csrc() = " + rtp1.csrc() + "; rtp1.ssrc()" + rtp1.ssrc() + "\n";
//            textPane1.setText(textPane1.getText() + "> rtp1.csrcLength() = " + rtp1.csrcLength() + ";  rtp1.csrc() = " + rtp1.csrc() + "; rtp1.ssrc()" + rtp1.ssrc() + "\n");
//            System.out.printf("rtp1.csrcLength() = " + rtp1.csrcLength() + ";  rtp1.csrc() = " + rtp1.csrc() + "; rtp1.ssrc()" + rtp1.ssrc());
        }

/*
        if (packet.hasHeader(Tcp.ID)) {
            packet.getHeader(tcp);
            printResult = printResult + "> tcp.dst_port = " + tcp.destination() + "; tcp.src_port = " + tcp.source() + "; tcp.ack = " + tcp.ack()  + "\n";
        }
        if (packet.hasHeader(Udp.ID)) {
            packet.getHeader(udp1);
            printResult = printResult + "> udp.dst_port = " + udp1.destination() + "; udp.src_port = " + udp1.source()  + "\n";
        }
*/
        textPane1.setText(textPane1.getText() + printResult + "Frame " + packet.getFrameNumber() + " \n" );
        textPane1.setCaretPosition(textPane1.getDocument().getLength());
        //System.out.printf("frame #%d%n", packet.getFrameNumber());
    }

}

