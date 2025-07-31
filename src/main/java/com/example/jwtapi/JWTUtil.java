package com.example.jwtapi;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

public class JWTUtil {
    // Generated 2048-bit RSA JWK
    public static final String JWK_FORMAT_RSA_FULL = "{\n" +
            "  \"p\":\"4TvQE-u2L7Wo7IWKkVogJzGne0QTBzHCqTnCh4K58TGKgbMPUINiTkRFdQ9l3lavta7_6WJ9dCrm4IoLpri4JoFSzhxPxGkimJ9eEKn_FElrQcx5VAvP9lBT95CTpp4v83Jl3fjUC63jTqM59ESMkf_DOjeM_-JPhMN73MvqU9U\",\n" +
            "  \"kty\":\"RSA\",\n" +
            "  \"q\":\"82IgSfybWK8NN8YvisNQoqqZtWDZPgERWrQOQA3jRoBelF79_-VO_jU8TmaCwmIHZsSwQnBlenqVOy_0BrpGoD_ppUAFWvRKqnJMHfE26mS6CX2fvRlN254iTzQQWerMVE34mnPFElZ8pfxt6RdBxB7TGVXKTR_BdqvwvT_8wfM\",\n" +
            "  \"d\":\"ICwybxL9lBHxxHY4jgvthHbECE_qwQNsc3zOto97ryDqqb0yQ8thV5lMCZyLmemOEVnT-0CiuMzPEud1JtiMU-HWP3332rvU6SdCs6Bt-V0RTLQ3hKZPrElUm_3_65bZQmLPyRmkxguIN5ZuiN8ItNv3XTgo8W152hTuszWLIPMeiutR1L5aJAte25T3q9mtdcN_AXNYowF8fHMLGdBKTD4eqiKDWnaBO-C6jgLa9fIW4VaCr1_6OYbP_WHCkOhJ4HM7YPy9kPrERHqdR8TD1fkniCcQwy8R0VXj9fK4xHvjPqOOwBnp20CoMWZnJjeTtkSIfTrKtno4RX4aedWi4Q\",\n" +
            "  \"e\":\"AQAB\",\n" +
            "  \"use\":\"sig\",\n" +
            "  \"qi\":\"B7z9l5BhZQ6LNdO7Rl3fS8XEB9_vno6ARfHvca0783OJ6HhFeHRyIgCPVl0afL95G-q5Z1qNB0y5yj4ZpK9QAt4lQ-gCFg41p5J7OpCYQlWRTV1QW4T1_0asiKgXSOfhcB292NjfK-QMHbSDdNs7lzvQIpPfAAXm4zUBMSonJ-s\",\n" +
            "  \"dp\":\"x21adAkFK4FBrQshAko2pf2FOdOwtXIN1iDaaXoKgdFHvkd5i-SJKpuwlFGp9Q_0TH5DAba_Nhi2jKIuZtSv2Qgw9WaECni8tT6G32JmBORtH7mYxB4haQr_Dfjpg2IVOw1TvRMRTbYNyhckvW_kt3Eqv2VoZzlPB1K_XWUAenE\",\n" +
            "  \"alg\":\"RS256\",\n" +
            "  \"dq\":\"TNfqgfGzyqhacAWu9Qz95J4gsdfGP4FuzUiURz0bSSM2uXnUkHsCGdkNFWPgXSc-VwA69n8uSyFxBKL7VTRzIB2N05MHHdSLzo0P41RJlm__HQgA61-V6YVgJ8m0b-9mXCfSGlH7IvMToAS3XyTsqtNgq1se6ILiPmnDNL2DPGk\",\n" +
            "  \"n\":\"1iIb0SKujD3a773rqJ9X0PeW30ZqKwGh9ekb7Gbxk_caYTJVXuLFvIqdhf6t-j2z85ZXaw-miFv_TJsXkArCYIdRUtrJoQt2_tNqzuRYKimHRg_8fJkxQckLeUp1NWL0oJqpZ6aCZq9tqB_GBbDvkOqm-g9X6qy3XZkikIYt22zCKK50Kfp-twKwG0uuzaR5JWNAO73WyGSW2rP2G4AaGuL08AHPNCd_fnIWwxv94wihNBRjTUm4b12BBbe2QQxMefWXWTc9DFHW_7-mkvHMfMYkvc6zMT6seCSspNp2PH9FkFyZlvDwiE4od2hxOGorojdP9UhBOGkRVgHeKU0oLw\"\n" +
            "}";

    public static RSAKey getFullSignJWK() throws Exception {
        JWK jwk = JWK.parse(JWK_FORMAT_RSA_FULL);
        if (!(jwk instanceof RSAKey)) {
            throw new IllegalArgumentException("JWK is not an RSA key");
        }
        return (RSAKey) jwk;
    }
}