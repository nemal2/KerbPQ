package pqkerberos;

import java.io.*;
import java.net.Socket;

public class MessageIO {

    public static void send(Socket socket, Object message) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(message);
        oos.flush();
    }

    @SuppressWarnings("unchecked")
    public static <T> T receive(Socket socket, Class<T> expectedType)
            throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        Object obj = ois.readObject();
        if (!expectedType.isInstance(obj)) {
            throw new IOException("Unexpected type: " + obj.getClass().getName());
        }
        return expectedType.cast(obj);
    }

    public static byte[] toBytes(Serializable obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectOutputStream(baos).writeObject(obj);
        return baos.toByteArray();
    }

    @SuppressWarnings("unchecked")
    public static <T> T fromBytes(byte[] bytes, Class<T> type)
            throws IOException, ClassNotFoundException {
        return type.cast(new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject());
    }
}