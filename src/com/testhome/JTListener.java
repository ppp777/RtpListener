package com.testhome;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.*;
import java.util.*;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Sip;

public class JTListener {
//    private JTextPane textPane1;
    private JTextArea textPane1;
    private  JTextArea textArea1;
    private  JButton startButton;
    private  JButton stopButton;

    public JTextArea getTextPane1() {
        return textArea2;
    }

    private JPanel windField;
    private JButton initButton;
    private JTextArea textArea2;
    public volatile Boolean stop = false;
    final StringBuilder errbuf = new StringBuilder();
    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs

    Dumper dumper = null;

    public JTListener() {
        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dumper.start();
            }
        });
        stopButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dumper.stop = true;
            }
        });
        initButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int r;
                try {
                    r = Pcap.findAllDevs(alldevs, errbuf);
                    if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                        System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
                        textArea1.append("Can't read list of devices, error is " + errbuf.toString()+"\n");
                        return;
                    }

                }
                catch (Exception ee){
                    System.out.println(ee.toString());
                }

                textArea2.append("Network devices found: \n");
                                int i = 0;
                for (PcapIf device : alldevs) {
                    String description =
                            (device.getDescription() != null) ? device.getDescription()
                                    : "No description available";
                    //System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
                    textArea2.append((i++) + " : "+ device.getDescription() + " > " + description + "\n");
                    //textPane1.setCaretPosition(textPane1.getDocument().getLength());
//                    list1.add(device.getName());
                }
                dumper = new Dumper(0,1,alldevs,textArea2);

            }
        });
    }

    public JPanel getWindField() {
        return windField;
    }



}
