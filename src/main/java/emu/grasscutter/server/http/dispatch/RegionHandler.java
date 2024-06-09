package emu.grasscutter.server.http.dispatch;

import static emu.grasscutter.config.Configuration.*;

import com.google.gson.*;
import com.google.protobuf.ByteString;
import emu.grasscutter.*;
import emu.grasscutter.Grasscutter.ServerRunMode;
import emu.grasscutter.net.proto.QueryCurrRegionHttpRspOuterClass.QueryCurrRegionHttpRsp;
import emu.grasscutter.net.proto.QueryRegionListHttpRspOuterClass.QueryRegionListHttpRsp;
import emu.grasscutter.net.proto.RegionInfoOuterClass.RegionInfo;
import emu.grasscutter.net.proto.RegionSimpleInfoOuterClass.RegionSimpleInfo;
import emu.grasscutter.net.proto.RetcodeOuterClass.Retcode;
import emu.grasscutter.net.proto.StopServerInfoOuterClass.StopServerInfo;
import emu.grasscutter.server.event.dispatch.*;
import emu.grasscutter.server.http.Router;
import emu.grasscutter.server.http.objects.QueryCurRegionRspJson;
import emu.grasscutter.utils.*;
import io.javalin.Javalin;
import io.javalin.http.Context;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.slf4j.Logger;

/** Handles requests related to region queries. */
public final class RegionHandler implements Router {
    private static final Map<String, RegionData> regions = new ConcurrentHashMap<>();
    private static String regionListResponse;
    private static String regionListResponseCN;

    public RegionHandler() {
        try { // Read and initialize region data.
            this.initialize();
        } catch (Exception exception) {
            Grasscutter.getLogger().error("Failed to initialize region data.", exception);
        }
    }

    /** Configures region data according to configuration. */
    private void initialize() {
        var dispatchDomain =
                "http"
                        + (HTTP_ENCRYPTION.useInRouting ? "s" : "")
                        + "://"
                        + lr(HTTP_INFO.accessAddress, HTTP_INFO.bindAddress)
                        + ":"
                        + lr(HTTP_INFO.accessPort, HTTP_INFO.bindPort);

        // Create regions.
        var servers = new ArrayList<RegionSimpleInfo>();
        var usedNames = new ArrayList<String>(); // List to check for potential naming conflicts.

        var configuredRegions = new ArrayList<>(DISPATCH_INFO.regions);
        if (Grasscutter.getRunMode() != ServerRunMode.HYBRID && configuredRegions.size() == 0) {
            Grasscutter.getLogger()
                    .error(
                            "[Dispatch] There are no game servers available. Exiting due to unplayable state.");
            System.exit(1);
        } else if (configuredRegions.size() == 0)
            configuredRegions.add(
                    new Region(
                            "os_usa",
                            DISPATCH_INFO.defaultName,
                            lr(GAME_INFO.accessAddress, GAME_INFO.bindAddress),
                            lr(GAME_INFO.accessPort, GAME_INFO.bindPort)));

        configuredRegions.forEach(
                region -> {
                    if (usedNames.contains(region.Name)) {
                        Grasscutter.getLogger().error("Region name already in use.");
                        return;
                    }

                    // Create a region identifier.
                    var identifier =
                            RegionSimpleInfo.newBuilder()
                                    .setName(region.Name)
                                    .setTitle(region.Title)
                                    .setType("DEV_PUBLIC")
                                    .setDispatchUrl(dispatchDomain + "/query_cur_region/" + region.Name)
                                    .build();
                    usedNames.add(region.Name);
                    servers.add(identifier);

                    // Create a region info object.
                    var regionInfo =
                            RegionInfo.newBuilder()
                                    .setGateserverIp(region.Ip)
                                    .setGateserverPort(region.Port)
                                    .build();
                    // Create an updated region query.
                    var updatedQuery =
                            QueryCurrRegionHttpRsp.newBuilder()
                                    .setRegionInfo(regionInfo)
                                    .setClientSecretKey(ByteString.copyFrom(Crypto.DISPATCH_SEED))
                                    .build();
                    regions.put(
                            region.Name,
                            new RegionData(
                                    updatedQuery, Utils.base64Encode(updatedQuery.toByteString().toByteArray())));
                });

        // Determine config settings.
        var hiddenIcons = new JsonArray();
        hiddenIcons.add(40);
        var codeSwitch = new JsonArray();
        codeSwitch.add(4334);

        // Create a config object.
        var customConfig = new JsonObject();
        customConfig.addProperty("sdkenv", "2");
        customConfig.addProperty("checkdevice", "false");
        customConfig.addProperty("loadPatch", "false");
        customConfig.addProperty("showexception", String.valueOf(GameConstants.DEBUG));
        customConfig.addProperty("regionConfig", "pm|fk|add");
        customConfig.addProperty("downloadMode", "0");
        customConfig.add("codeSwitch", codeSwitch);
        customConfig.add("coverSwitch", hiddenIcons);

        // XOR the config with the key.
        var encodedConfig = JsonUtils.encode(customConfig).getBytes();
        Crypto.xor(encodedConfig, Crypto.DISPATCH_KEY);

        // Create an updated region list.
        var updatedRegionList =
                QueryRegionListHttpRsp.newBuilder()
                        .addAllRegionList(servers)
                        .setClientSecretKey(ByteString.copyFrom(Crypto.DISPATCH_SEED))
                        .setClientCustomConfigEncrypted(ByteString.copyFrom(encodedConfig))
                        .setEnableLoginPc(true)
                        .build();

        // Set the region list response.
        regionListResponse = Utils.base64Encode(updatedRegionList.toByteString().toByteArray());

        // CN
        // Modify the existing config option.
        customConfig.addProperty("sdkenv", "0");
        // XOR the config with the key.
        encodedConfig = JsonUtils.encode(customConfig).getBytes();
        Crypto.xor(encodedConfig, Crypto.DISPATCH_KEY);

        // Create an updated region list.
        var updatedRegionListCN =
                QueryRegionListHttpRsp.newBuilder()
                        .addAllRegionList(servers)
                        .setClientSecretKey(ByteString.copyFrom(Crypto.DISPATCH_SEED))
                        .setClientCustomConfigEncrypted(ByteString.copyFrom(encodedConfig))
                        .setEnableLoginPc(true)
                        .build();

        // Set the region list response.
        regionListResponseCN = Utils.base64Encode(updatedRegionListCN.toByteString().toByteArray());
    }

    @Override
    public void applyRoutes(Javalin javalin) {
        javalin.get("/query_region_list", RegionHandler::queryRegionList);
        javalin.get("/query_cur_region/{region}", RegionHandler::queryCurrentRegion);
    }

    /**
     * Handle query region list request.
     *
     * @param ctx The context object for handling the request.
     * @route /query_region_list
     */
    private static void queryRegionList(Context ctx) {
        // Get logger and query parameters.
        Logger logger = Grasscutter.getLogger();
        if (ctx.queryParamMap().containsKey("version") && ctx.queryParamMap().containsKey("platform")) {
            String versionName = ctx.queryParam("version");
            String versionCode = versionName.substring(0, 8);
            String platformName = ctx.queryParam("platform");

            // Determine the region list to use based on the version and platform.
            if ("CNRELiOS".equals(versionCode)
                    || "CNRELWin".equals(versionCode)
                    || "CNRELAnd".equals(versionCode)) {
                // Use the CN region list.
                QueryAllRegionsEvent event = new QueryAllRegionsEvent(regionListResponseCN);
                event.call();

                // Respond with the event result.
                ctx.result(event.getRegionList());
            } else if ("OSRELiOS".equals(versionCode)
                    || "OSRELWin".equals(versionCode)
                    || "OSRELAnd".equals(versionCode)) {
                // Use the OS region list.
                QueryAllRegionsEvent event = new QueryAllRegionsEvent(regionListResponse);
                event.call();

                // Respond with the event result.
                ctx.result(event.getRegionList());
            } else {
                /*
                 * String regionListResponse = "CP///////////wE=";
                 * QueryAllRegionsEvent event = new QueryAllRegionsEvent(regionListResponse);
                 * event.call();
                 * ctx.result(event.getRegionList());
                 * return;
                 */
                // Use the default region list.
                QueryAllRegionsEvent event = new QueryAllRegionsEvent(regionListResponse);
                event.call();

                // Respond with the event result.
                ctx.result(event.getRegionList());
            }
        } else {
            // Use the default region list.
            QueryAllRegionsEvent event = new QueryAllRegionsEvent(regionListResponse);
            event.call();

            // Respond with the event result.
            ctx.result(event.getRegionList());
        }
        // Log the request to the console.
        Grasscutter.getLogger()
                .info(String.format("[Dispatch] Client %s request: query_region_list", Utils.address(ctx)));
    }

    /**
     * @route /query_cur_region/{region}
     */
    private static void queryCurrentRegion(Context ctx) {
        // Get region to query.
        String regionName = ctx.pathParam("region");
        String versionName = ctx.queryParam("version");
        var region = regions.get(regionName);

        // Get region data.
        String regionData = "CAESGE5vdCBGb3VuZCB2ZXJzaW9uIGNvbmZpZw==";
        if (!ctx.queryParamMap().values().isEmpty()) {
            if (region != null) regionData = region.getBase64();
        }

        var clientVersion = versionName.replaceAll(Pattern.compile("[a-zA-Z]").pattern(), "");
        var versionCode = clientVersion.split("\\.");
        var versionMajor = Integer.parseInt(versionCode[0]);
        var versionMinor = Integer.parseInt(versionCode[1]);
        var versionFix = Integer.parseInt(versionCode[2]);

        if (versionMajor >= 3
                || (versionMajor == 2 && versionMinor == 7 && versionFix >= 50)
                || (versionMajor == 2 && versionMinor == 8)) {
            try {
                QueryCurrentRegionEvent event = new QueryCurrentRegionEvent(regionData);
                event.call();

                String key_id = ctx.queryParam("key_id");

                if (versionMajor != GameConstants.VERSION_PARTS[0]
                        || versionMinor != GameConstants.VERSION_PARTS[1]
                // The 'fix' or 'patch' version is not checked because it is only used
                // when miHoYo is desperate and fucks up big time.
                ) { // Reject clients when there is a version mismatch

                    boolean updateClient = GameConstants.VERSION.compareTo(clientVersion) > 0;

                    QueryCurrRegionHttpRsp rsp =
                            QueryCurrRegionHttpRsp.newBuilder()
                                    .setRetcode(Retcode.RET_STOP_SERVER_VALUE)
                                    .setMsg("Connection Failed!")
                                    .setRegionInfo(RegionInfo.newBuilder())
                                    .setStopServer(
                                            StopServerInfo.newBuilder()
                                                    .setUrl("https://discord.gg/T5vZU6UyeG")
                                                    .setStopBeginTime((int) Instant.now().getEpochSecond())
                                                    .setStopEndTime((int) Instant.now().getEpochSecond() + 1)
                                                    .setContentMsg(
                                                            updateClient
                                                                    ? "\nVersion mismatch outdated client! \n\nServer version: %s\nClient version: %s"
                                                                            .formatted(GameConstants.VERSION, clientVersion)
                                                                    : "\nVersion mismatch outdated server! \n\nServer version: %s\nClient version: %s"
                                                                            .formatted(GameConstants.VERSION, clientVersion))
                                                    .build())
                                    .buildPartial();

                    Grasscutter.getLogger()
                            .debug(
                                    String.format(
                                            "Connection denied for %s due to %s.",
                                            Utils.address(ctx), updateClient ? "outdated client!" : "outdated server!"));

                    ctx.json(Crypto.encryptAndSignRegionData(rsp.toByteArray(), key_id));
                    return;
                }
                
                if (ctx.queryParam("dispatchSeed") == null) {
                    // More love for UA Patch players
                    var rsp = new QueryCurRegionRspJson();

                    rsp.content = event.getRegionInfo();
                    rsp.sign = "TW9yZSBsb3ZlIGZvciBVQSBQYXRjaCBwbGF5ZXJz";

                    ctx.json(rsp);
                    return;
                }
                ctx.result("{\"content\":\"d1EHuraW4XpdD6bXP/C1id2Zz/2lYiqi3iQbECHnZCml6Rhs+o+xXZc8hPw7pPEe7joyYx1cuMfwRiRnNUX9YaDDa4yullc3kj+Gg6ZfOKwU6PhdcVrOAsT3eJhXUYEdOJlJw+X/6UrQ452iRE5nTSShUWE5oSvA1Hc3hbI9gRXjRzgCrOVmqBBeaRhYprzprBMPdCNnt2VRaQuDb1j6x8tjRxcXSi6grHxwAU3dH1V2NWxBDS9Z78cbl7B6k0iJbqFkaW5u1CCz8RZWqdHGZAiMgexpu3D4EBeIPTPyldl2sEe964vBFUjV9WDA9cjd0XsfL/55xeGRxNL8/XK+zhKngoxLtlkpQq3NK/NnK1D8iT89/VIDrh8i+DCNbWrt0H/4cl/BqQWzpmxNRlnHrZlkK8BSiO3bO/3l04dNpTZKJjp1117jOHBKw4ZlCHUltt4oSr1hwqZvn5namUnJkOBeOxu/isN159Q323k0N67Obz0fLRGYO8WWUgKvvvQZslEKL0P82DOeKQhs5s3nDKPc1jluzHbB1m1Gc8oytn/bOqImmttCDrTox3dr3rTXrJ4Dzkh5datefNmZ/jG+nSwVstuptK8tHMPqw4AB06IreUaX1qwxKLDiMWXaJ9sX/nvnVK7nCJ4jwnmJKNLuaxgsg74c9LIWX8sUaOSPTF02TVHLaJhU/MfUUZ8Imkw8dDg2R2RjTDAuo+5FUsRvJEo1Bfqzt+a5i9qWp4PaxJF6Q+Yg6cMTxPeomyY8l09VUGHNHJsj62MpmcuQgQkT8aTuVgdLEaIRhhvfd/cxZ+VQjl6bpyay3TILSE0LXfFPkkqq4CNp7Z27k3C8yxtAwms0zwHWWp40effFFS99+qqmtLjU5LGqapydTwyRzDZL6qA3TSLf0GelfRpCyyod2XVe5m3dTbCK+W5Y7NW2ZHx4i7jocLg94U/3zT8UNWwl08re8Y34z4jXAYNYigFKaHxseGr/HAdM0bHgy+sI5RsZdlRntqKeZKLn1Pwij2XGm5LZtueOst/ep5dOcGNCx6E9X/D2dsdEP7e8YzqcWsOePpBWtwzI+Bg48MO5cwYrmA9v9gYLG72tzb5swR4mwryX5Z1/8fJWa9rH4FT77Tj65HI9hNldVYCTBOXvW5KEg0EYOKq/xfiGxb0tK29a/qe6+16blMR84u44qszVz9/JwPfBu+xFMg+HGUVLHrDUrtqLBqTd0AdeGQ10u6mOdk9aA1MSIOBZIawk2LfUpgmKJ2yJ2u5810AJMNTN1tDiH1O+e4/LsZjDFivbu4dwAA0zfPXNi+QdRzC4NCPNpAwH1bXWh/rp6FSIfMhbh6GnazFupES1UXwqcldITJxbNpV+LXxPuGGP2SqyTjrKMtPwQL9lAnoASOdCSyh9J7BDOp4ia4ldF8LGe8d+gpmFVTTpn/1O1O3Wq1IEcn2SDqCLLkscoP6JecuJgmugP82rVZrk5vrNVLAar0ytJZj/aCSomFJd0E2dmllTEf+vhqJ92TSNjxM0oO+AanomDb/6oF2iPuvgNPxtVLrHUnwFvM/zh3lOsdY64uJiCoPuQbvUR6LIDz00xlCASBqoYlDYuhtxNBiQK4HR2pyIMsW+sS1PeUIvcd2BVVDNI5zRuJG+60eX/pQyXfcR+Iy6DlhTO7x/yyFsXJTGstL5lZBGEfouQMNX71tnvqlD0gHzVoCvuVJzfp3yhcpgLmSG/1Ulm2jxLnl2BaA5c2pcv3BodvPJ/fcX6CRvU9gRwSHBguv3+rdta7J9//zu+/bXOf3RamvyKlTbSkhskd1b5pQ2X5P8jMGZUX64FLw65pI/xQPtfUdFVhY4mzv3wNicbfCOUHMFuQ+O1grP8Z0FNcrWsGLZxnirLTz03cJNmXWANppkNXOZ6EsPObXBktspbFgHxKSiCXx9+maCxFaPQLk9jhoeSgBiHGOMG+MJeHZG3wNm5T7sCL37kDHYxV1Lncgjao6SukaSkgOjNrdX5fCmXDpuCtMD3YXpDxcU3fxYQk8W/ezX7yME7zXnqJ/rA+wJmZBdn74qIaJNgRBJIjzRNv52vqQ2+OJ6kMMJ9fkAUVcTvKVERVNLya3g71hIazhwtC8043cmZJu3IT4LcIaaR7STDTtC7rozZmzj2uhcGlbUDM05KzHfsc5BK1uy7hkMjlKr0o5nC/RScBAKjljClZTnBa0Y5RWaEKc/FY2XCgQ2Mo2qfkoaMLQd4bNO+xW+Whtz+1jmXhJM7bf5DNndzQ4u4rh/2XTfVR4FqmvI5BiovObfjnci1c9H83LlKEL0uk3o4kLe7ofq/4oSxSW/d3yLtZmSUx0Ks0obzDFg9GP0P2bbPbKj4QNZEZxNrDhAJi2oglb2nd325TYYrhbDN5cmp9By2YXpiJwLabf4HrhvB9tYJj/M1Q46djQFkf/xfyD2Wg0ptwNQE0OPGDvHFIjmOrxqrnuYeMibeB6YZHEI+Q+W2Bj7aj7Un7Vtt21YR6tSeoVhbuWeUfXgzseemcXn3b+WLnKqj8YqhEA1H9bt6iNqUtdkQ4IEw9FHLuYSfeE/Kd40FCYrnIs8pI1zs4xN4jeBbp0ATawkKW6X4Oks0C8Yf3IhIqR1prBeqAyPRngefQX/fivYHADBT0mNMvKEDlgsy/C/tfGG2Qq/tU4BV0PiPU8tfQPxXnRfurPVky/7N4r7u2JXtuwdCUl8KcLnlFr+H9+oStPAydXRVLY+W97pne0rPc2I9HnWgMZefgc8TSR9PdfwE9LLD5C4qqllNIn22naz++aoEZYbmz7hHfYcZvZ8WUWE+xwkOLUuQd38u3tG1xq7QOlBn04fa7rtWgdctLJlxGPWqHUTj+l9udUNy9s+yP5u9JdacGyDEAD3Z3m27kyncMZMdd+xk7EFhE+j4OQE/cVY7V3T//Al25mIxVDdcco31t9e2XAWABIxazvNqTUbgkzysGZGamNIhE/KHEQG7VcI7L736Bf8hrLVCmvZmxo/CuieErrdTGdNtcqLWPd0tU2VsAAiNKewoOzMsfU4c3js4bvo/aC5aRb/ItNbx20u+jA/SsepfH1Gc1087BfhCGwtFQbz1VtWL4aGkJ10FpMGcaBWuhH5sui4FeoPGuqh2bWCx33AtHjKUa1wcASiggEh12+2+NbUa4ph10bcu/q+UPsZEua72TuaK2TDcCvrxAS/13RTg806PdKjteBY4aws+WlbmQ4n+7BT0p2VffMX4QBNiRD6i2Mu55E+6LDatU0xtgZEejuFT/kmr64hsUcjVWUvdYRQMde8kaT7q8cC455D1TC+7CmfjWOroKLuwGAxWTi1Zu0aIROyUDt8Eedj8+9vDmvfDoK2WVpIdXU0wEvb3vgu6v8M7AuZjXISLLFpaXleqmvb+202tMfF1K4FYRPtuzh3ru9AsvSKlZ+j4007RvPuNGJwbhR5CkEyWpljOrPSarHrL85Adta336aUcGOoKewBSpHATqIaU7gNppX0z3Fr+BGXvmYOEcWCliSXPHJWNkZjTxsABneD94Tsru9voh68myVAxCqgeYaYa3xLf285X3+7sZ556p43la6dMxBW5Z8UayB921dsuCpKoo49xhuWXNsdI56lty35QF7zRqJCpPGMJ5FrV57fOy91tCcOv7el+OXcV7UkfA6lkYLfR/ZacY/9UPCjqTVQ1PaXaKKZVHHF4mu017nCVLrKX4puEO1/YsZA9N4MBnjgaLRpQw5J1wxSSi+Dzj0q6Q+aTkuNlWXRQvC0qB6p3p4azmfGZog9bObd16zVSDjkbVf9CsyaQYjot6P+FQIwY9b3qwR44/sUYm7sdk93hfuUL/Mf9RM6yQfPvp1c6etI5TQ/YdakZeQ/4GulWEEzp9c7ckqrTd3wmbpRcfrExnhmu0/EdqilImYDiLNpuz8YDiTWWgWOpls6TXdDs0H0/aJCaZn0Z+z4Ok5/I+O+DoVLvfvPh1of4zyAWaAitia6+uX8jCVTjSiUWI3NW8QWYQvAWLav4IFDmFtwgp7Nfq+rsgBxveYqafDmXY9Kj7a5inhUbtSRYzSBBEBLFlNNl0fGquMFz/1UiMCog/wMLr7IXEgID0f1A5ATUcR9Hc59RhKBlvP6DfEK53ovVNIQ0molVR+SVZW4EnjwlKqsQy6bbIMRjfM2JRe535mDk9zWdO4i7mtZFVY3/f0Qi8RLhUrvZAjOq/K0G8lVTJGE4KwM+pFZkasGiPHoVo8dB9tsVyKN72aylDTA6kPgkNu2xID8/XWGcQdg58+3ym1KI3gJeuGhJ0hyp/x1bX4LDv0a/3ux41e+G4RS8JcgKnrrdGi7Zg9SD+Kwj2Ji+Y/5sFMyKAJcmF8lS9/Zmcwa5O0TRVS61usg/4LaE4tMnQ3xjNj0r1XuPeBhtOfx4HXoC/vR5P+A1gBcV8yiePCSXVFVeTA9Vm/qXwcV7qPRZV/XtMjjxSjm+5+judWIAX3Xr7rU3AWarpXxMKNiHBjXSvMgH0s2VOH/WzwbzNQpgRrF2gDy8z8zpdD7Iqa8ursDEv7Bpzh62oIZce7JAwvcOFau3kVM/7PBEMiQxvE3+thP17zWXJMAVspRhtiSUE0fVJpwxITaX/YUVD2eXvVOud8qk3cnyaiI7MHe4tWxFkQHdlTSuItgJXzK9PLZy4H8TT9+NSXHzCGPVfdNctySAQxELhZW318xBUkzIOcEe2M1wB9qpiL24dLvVLRpCvxrh3QTXKu7V4q3pDI+cr0wC7oMlcYC9NQj9B3bqz6rt3iOcY6Zyf4ExhL3kfRnmh49BnUqKnG0AavRQXbFEdi2OyQh1Iey8xbNEjDg91N0Mit4yvMm+YSXzs7FNI5Z4JrcbOwcbGu9L94weoR0esSleCZ8pENoDlxa4yhOXZHxzRCE/DUWWFLck4C1Jf7GocowJhyCaropNfEZq/+5Zg6TAZ9ZYtMiZn5X+Ub7JuJV9kRSPt6YQ20qBvHEgLJii+XLue6sE2P+l4kb8EM0Evd7xVd0qt6yHOYxQEOaxsIUzfHdtpnQ/ht3dVFQnRmGKg6pmZjanIV+jm34qI19rHm0+OZ6+bwP2WY8Kt7/gtZE8HJO2wjxh2ecX7hjnILrrhfmCzdQYjJambPc/b7UNohPX4ea+tsEMGZpyUC28yzDlzgtT3mymEYhODev58WP7GfDawvvsRmBG7GHlxwI/GtzYxcdH0lR4oqxjn2vseNPEFsU29+uO2WgniiSLt2gR1gCvCi2xUY2ZVjXpxNC7v6VbkO4XQ/gs9v3oeBo1zKYuxwdVZu1xOy60vBu7uYJXkp3hnZvxLJl9OELiApw3WUH/W6egCbcncumFJQnC9ndpzZEOGE8U4ZE2AQpNCKIZaAR0/PhdnkXRawZCqT7xcnne4xvP8iT8S/JTHH+ch5w3s6Gpf7LH3dsK0T0GVQpbmF52TX81qxTdZ/CjIEnNmQcUlS+2mRjKqDDkBCfZ4Swh8orbW4MbQ+B10GcoKQ3t7VYYIjK4w1Cb+M/U1xCJB4Fe/0qql1snnD+5jkmAVc5+1TmS2ZzxBfyHveneT6pn9/rV++gjAQfNX7BbasXOH90N+mzI307tQJjhDyBaZsLEcV+8U2gZ0yvzPjv+xN2ctPRGRiY1OZ/EohCT2Os1zrYktMXLcmzw5ejN3bR2efiS0fvM/yp0u8P4IwhJ+i4ZOcJ9W4VaBB4WVYKsEOhZSb8SLxVd27UjTTz3KBOQMOKQRPnPsz2EToCh41BJf3NER5Nq68lC6EB2oCNKqBxbo3olK0DirnOobePxN3lrVMWFxv4VCLdpRoJLeu99rPdv+8mCKPhWNb7HoUmg0tXHvdq5KgTzdyAcgKuwY3DYYOxx1XG+Y5syHpQXtmaALBKEr8efgwHvT7xUKazWRLfbWteA/aUcK7c+j2tIS9REWXVgKAw/AxcNX4KXNjrPEcRU+iwfki3D2lz8Y7MWnHs3IejiDiwxpft1ysjRmcbRpsPSzUdAKbLp4FgM+tlfyaysIF+RNNPo5By3nWC7cHK8Goa5vfwJX/Mf5pXSDE16s4/Svkr0QgfYr2xy48DjmdSE2GS+0l0Y6W5kqBQTaYLizl+QB1Ch9HrOAce18/bjd2xX93Jl9OzvpKjuoFbj/Lpt2iOSNR+LeLUWgJQsiN6j8tSLGEqcdGOLHe1riGA5IKD9LKoCUTx3fndZ169Jx156HjSkh+tXrj7CJflWAa7Jw+sEq4IndHtlxV+cGeirk/C0K2ZdKPy96J4+x4BzBk41DK6FryHhFrdut8tyl8BTqCDDIlGO0OpANXWOt6qchsxK8IIrKEVgy8T59cT8UCN3d3WQCV9vfYAfdBWC/c73W7CcvxfAMiEEmO8qhScbrBkXLYZaytub3IK0HF5kdSuXY9Tk5FAGXWYnPTlAK8jTrhHkgHKYVa2/aQ44UzZQFjASp4JMPqod18+K1CkZwzJGqKt0wrJzFBHIlvL5+5uoCFH9Tq2o7r6SH8nwkIK62y4/n1QY/SXvsoRB2IPUomh0N++2ljhEPQAG/+/Di1O0467lc//zyuxFVhWTUGEfzVbZJQuw5Zyhz0LMWGA/2MAr4TR6nQfBTnDkc9ysqsq8z08Z1C8+sHWx03WyzlXFxM2wV+4Ap2hl2iCMAUH9icMrOwBytU2UclWyNNe6cnVHJHfbJIFQDkkjr/YTnX0ErE6LdyxKWvFljr30HCrWP6VunrNHtQWRaQwmlotu/0QARZZgdofOiviWg+3s5T5L0XHUZjnwoUS+hB8D4tWCscDph+Vz45M/WVYwlLM7UsLt4tb4G1fPfJdQun0UYT4ZNdqaGzSKnEGv2k=\",\"sign\":\"KDnU6l9kZjsi89vZ1dEvIeC3ComSLpfFclQTKRaOxjHM63orxs8h2iMMuFm15wCrcEt0HSVtTxcbrBqw4ZR9ImOYsNsrq/QhORpNqBoeSuwt3BX05I8cRrJmL0s8JYwsh8gqZuMc53LNm8ebkAa16uoPy7WPNjU8mp+Oq6UzA0g4QR3M8c5CR4aeSSWt45NGpu4lDlXCtSwHqOJoSeBnNdyCoWLEXrsEaPLeACGo0C9E6vns5ZGGXh/iUI8R+mNcNu9vQduhwuoETNfvLUpXOpDqu6Awasin2NBWybwg3qlGbFYBJQc7Jw5yVq9k0QDaj/p3tQJr/VKEwi2+eW52mw==\"}");
                var regionInfo = Utils.base64Decode(event.getRegionInfo());

                ctx.json(Crypto.encryptAndSignRegionData(regionInfo, key_id));
            } catch (Exception e) {
                Grasscutter.getLogger().error("An error occurred while handling query_cur_region.", e);
            }
        } else {
            // Invoke event.
            QueryCurrentRegionEvent event = new QueryCurrentRegionEvent(regionData);
            event.call();
            // Respond with event result.
            ctx.result(event.getRegionInfo());
        }
        // Log to console.
        Grasscutter.getLogger()
                .info(
                        String.format(
                                "Client %s request: query_cur_region/%s", Utils.address(ctx), regionName));
    }

    /** Region data container. */
    public static class RegionData {
        private final QueryCurrRegionHttpRsp regionQuery;
        private final String base64;

        public RegionData(QueryCurrRegionHttpRsp prq, String b64) {
            this.regionQuery = prq;
            this.base64 = b64;
        }

        public QueryCurrRegionHttpRsp getRegionQuery() {
            return this.regionQuery;
        }

        public String getBase64() {
            return this.base64;
        }
    }

    /**
     * Gets the current region query.
     *
     * @return A {@link QueryCurrRegionHttpRsp} object.
     */
    public static QueryCurrRegionHttpRsp getCurrentRegion() {
        return Grasscutter.getRunMode() == ServerRunMode.HYBRID
                ? regions.get("os_usa").getRegionQuery()
                : null;
    }
}
