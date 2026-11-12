///|
// Fixed synthetic public-only P6 signed assertion reused for bridge tests.
fn bridge_fixture(command : String) -> Json raise {
  let text = match command {
    "verify" =>
      "{\"command\":\"verify-assertion\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWTJoaGJHeGxibWRsIiwib3JpZ2luIjoiaHR0cHM6Ly9ycC50ZXN0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ\",\"authenticatorData\":\"-wzrYG4HT_Czv9YrnDzimTB1YeEcGdr8D8kazLmcUe4BAAAAAA\",\"signature\":\"MEQCIHZ25wrJ4zOqILaSqBnxOzlY33agrEFc1cpM4GRuAbvGAiBBiokpXZYjVrtv2AbpCZRgxghfu1YDBuu35h-s5BM8-g\",\"credentialId\":\"Y3JlZGVudGlhbA\",\"userHandle\":\"YWNjb3VudA\",\"expectedChallenge\":\"Y2hhbGxlbmdl\",\"credential\":{\"credentialId\":\"Y3JlZGVudGlhbA\",\"userHandle\":\"YWNjb3VudA\",\"publicKey\":\"pQECAyYgASFYIDZ7-LHDcH1N7DkagxRx8XEQ11pBAduZ0NyKRlPGXG25IlggPa8xmkOX7Dg9gut9xcvJ38vywx7SWwKiRTia-OZsVOY\",\"signCount\":0,\"backupEligible\":null},\"policy\":{\"rpId\":\"rp.test\",\"allowedOrigins\":[\"https://rp.test\"]}}"
    "register" =>
      "{\"command\":\"register-test\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWTJoaGJHeGxibWRsIiwib3JpZ2luIjoiaHR0cHM6Ly9ycC50ZXN0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ\",\"attestationObject\":\"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViO-wzrYG4HT_Czv9YrnDzimTB1YeEcGdr8D8kazLmcUe5BAAAAAAAAAAAAAAAAAAAAAAAAAAAACmNyZWRlbnRpYWylAQIDJiABIVggNnv4scNwfU3sORqDFHHxcRDXWkEB25nQ3IpGU8ZcbbkiWCA9rzGaQ5fsOD2C633Fy8nfy_LDHtJbAqJFOJr45mxU5g\",\"credentialId\":\"Y3JlZGVudGlhbA\",\"userHandle\":\"YWNjb3VudA\",\"expectedChallenge\":\"Y2hhbGxlbmdl\",\"policy\":{\"rpId\":\"rp.test\",\"allowedOrigins\":[\"https://rp.test\"]}}"
    "analyze" =>
      "{\"command\":\"analyze-assertion\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWTJoaGJHeGxibWRsIiwib3JpZ2luIjoiaHR0cHM6Ly9ycC50ZXN0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ\",\"authenticatorData\":\"-wzrYG4HT_Czv9YrnDzimTB1YeEcGdr8D8kazLmcUe4BAAAAAA\",\"signature\":\"MEQCIHZ25wrJ4zOqILaSqBnxOzlY33agrEFc1cpM4GRuAbvGAiBBiokpXZYjVrtv2AbpCZRgxghfu1YDBuu35h-s5BM8-g\",\"publicKey\":\"pQECAyYgASFYIDZ7-LHDcH1N7DkagxRx8XEQ11pBAduZ0NyKRlPGXG25IlggPa8xmkOX7Dg9gut9xcvJ38vywx7SWwKiRTia-OZsVOY\"}"
    _ => fail("unknown bridge test fixture")
  }
  @json.parse(text)
}
