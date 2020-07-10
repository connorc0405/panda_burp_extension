package com.ccumming.burp.util;

import com.ccumming.burp.PandaMessages;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

public class NetUtils {

  private NetUtils() {}

  public static void sendMessage(PandaMessages.BurpMessage message, Socket sock) throws IOException {
    byte[] msgBytes = message.toByteArray();

    ByteBuffer sendBuf = ByteBuffer.allocate(msgBytes.length + 4);
    sendBuf.putInt(msgBytes.length);  // defaults to big-endian TODO feel like the size is wrong.
    sendBuf.put(msgBytes);
    sendBuf.flip();

    OutputStream oStream = sock.getOutputStream();
    BufferedOutputStream bOStream = new BufferedOutputStream(oStream);
    bOStream.write(sendBuf.array());
    bOStream.flush();  // TODO is this blocking or not?
  }

  public static PandaMessages.BurpMessage recvMessage(Socket sock) throws IOException {
    byte[] len_buf = new byte[4];

    int bytes_read = 0;
    while (bytes_read < len_buf.length) {
      bytes_read += sock.getInputStream().read(len_buf, bytes_read, len_buf.length - bytes_read);
    }

    int payload_size = ByteBuffer.wrap(len_buf).getInt();

    byte[] payload_buf = new byte[payload_size];

    bytes_read = 0;
    while (bytes_read < payload_buf.length) {
      bytes_read += sock.getInputStream().read(payload_buf, bytes_read, payload_buf.length - bytes_read);
    }

    PandaMessages.BurpMessage msg = PandaMessages.BurpMessage.parseFrom(payload_buf);
    return msg;
  }

}
