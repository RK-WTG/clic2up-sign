///usr/bin/env java --source 17 "$0" "$@"; exit $?
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import javax.imageio.ImageIO;

/**
 * Convertit le logo clic2up_sign.png en ICO multi-taille (PNG embarque).
 * Toutes les tailles utilisent le format PNG dans l'ICO (supporte depuis Vista).
 * Transparence native parfaite.
 */
public class GenerateIcon {
    static final int[] SIZES = {16, 32, 48, 64, 128, 256};

    public static void main(String[] args) throws Exception {
        File logoFile = new File("../logo/clic2up_sign.png");
        if (!logoFile.exists()) {
            System.err.println("Logo non trouve: " + logoFile.getAbsolutePath());
            System.exit(1);
        }

        BufferedImage original = ImageIO.read(logoFile);
        System.out.println("Logo charge: " + original.getWidth() + "x" + original.getHeight()
                + " type=" + original.getType());

        // Generer les PNG pour chaque taille
        byte[][] pngDataArray = new byte[SIZES.length][];
        for (int i = 0; i < SIZES.length; i++) {
            BufferedImage resized = resize(original, SIZES[i]);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(resized, "PNG", baos);
            pngDataArray[i] = baos.toByteArray();
            System.out.println("  PNG " + SIZES[i] + "x" + SIZES[i]
                    + " : " + pngDataArray[i].length + " bytes");

            // Sauver le 256x256 comme fichier PNG (pour ressource JAR)
            if (SIZES[i] == 256) {
                File pngFile = new File("clic2up-sign.png");
                ImageIO.write(resized, "PNG", pngFile);
                System.out.println("PNG genere: " + pngFile.getAbsolutePath());
            }
        }

        // Ecrire le fichier ICO
        int numImages = SIZES.length;
        File icoFile = new File("clic2up-sign.ico");
        try (DataOutputStream dos = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(icoFile)))) {

            int headerSize = 6;
            int dirEntrySize = 16;
            int dataOffset = headerSize + (dirEntrySize * numImages);

            // ICO Header
            writeLE16(dos, 0);          // Reserved
            writeLE16(dos, 1);          // Type: ICO
            writeLE16(dos, numImages);  // Number of images

            // Directory entries
            int currentOffset = dataOffset;
            for (int i = 0; i < numImages; i++) {
                int s = SIZES[i];
                dos.writeByte(s < 256 ? s : 0);  // Width (0 = 256)
                dos.writeByte(s < 256 ? s : 0);  // Height (0 = 256)
                dos.writeByte(0);                  // Color palette
                dos.writeByte(0);                  // Reserved
                writeLE16(dos, 1);                 // Color planes
                writeLE16(dos, 32);                // Bits per pixel
                writeLE32(dos, pngDataArray[i].length);
                writeLE32(dos, currentOffset);
                currentOffset += pngDataArray[i].length;
            }

            // Image data (PNG)
            for (byte[] pngData : pngDataArray) {
                dos.write(pngData);
            }
        }

        System.out.println("ICO genere: " + icoFile.getAbsolutePath()
                + " (" + numImages + " tailles, " + icoFile.length() + " bytes)");
    }

    static BufferedImage resize(BufferedImage src, int size) {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.drawImage(src, 0, 0, size, size, null);
        g.dispose();
        return img;
    }

    static void writeLE16(DataOutputStream dos, int v) throws IOException {
        dos.writeByte(v & 0xFF);
        dos.writeByte((v >> 8) & 0xFF);
    }

    static void writeLE32(DataOutputStream dos, int v) throws IOException {
        dos.writeByte(v & 0xFF);
        dos.writeByte((v >> 8) & 0xFF);
        dos.writeByte((v >> 16) & 0xFF);
        dos.writeByte((v >> 24) & 0xFF);
    }
}
