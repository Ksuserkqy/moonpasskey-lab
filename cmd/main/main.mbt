///|
fn usage() -> Unit {
  println("MoonPasskey Lab analysis CLI")
  println("Usage: moon run cmd/main -- --input request.json [--json]")
  println("Commands in request.json: client-data, authenticator-data,")
  println("  analyze-assertion, verify-assertion, register-test (TEST ONLY)")
  println("See docs/CLI.md for the request schema and exit codes.")
}

///|
#cfg(target="js")
fn argument_prefix_length() -> Int32 {
  2
}

///|
#cfg(not(target="js"))
fn argument_prefix_length() -> Int32 {
  1
}

///|
fn cli_error(kind : String, json_output : Bool) -> Unit {
  if json_output {
    println(
      Json::object({
        "status": Json::string("FAIL"),
        "error": Json::object({
          "kind": Json::string(kind),
          "context": Json::string("cli"),
        }),
      }).stringify(),
    )
  } else {
    println("FAIL \{kind}")
  }
}

///|
fn print_human(report : Json) -> Unit {
  guard report is Json::Object(fields) else { return }
  for key, value in fields {
    if key == "checks" {
      println("Checks")
      if value is Json::Object(checks) {
        for name, status in checks {
          println("  \{name}  \{status.stringify()}")
        }
      }
    } else {
      println("\{key}  \{value.stringify()}")
    }
  }
}

///|
fn main {
  let args = @env.args()
  let mut index = argument_prefix_length()
  let mut input_path : String? = None
  let json_output = args.contains("--json")
  if args.length() <= index || args.contains("--help") {
    usage()
    return
  }
  while index < args.length() {
    match args[index] {
      "--input" if input_path is None && index + 1 < args.length() => {
        index += 1
        input_path = Some(args[index])
      }
      "--json" => ()
      _ => {
        cli_error("InvalidArguments", json_output)
        @env.exit(64)
      }
    }
    index += 1
  }
  guard input_path is Some(path) else {
    cli_error("MissingInputFile", json_output)
    @env.exit(64)
  }
  let bytes = @fs.read_file_to_bytes(path) catch {
    _ => {
      cli_error("InputReadError", json_output)
      @env.exit(74)
    }
  }
  let input = @utf8.decode(bytes) catch {
    _ => {
      cli_error("InvalidInputUtf8", json_output)
      @env.exit(2)
    }
  }
  let output = @analysis.run_json(input)
  let report = @json.parse(output) catch {
    _ => {
      cli_error("InternalReportError", json_output)
      @env.exit(70)
    }
  }
  if json_output {
    println(output)
  } else {
    print_human(report)
  }
  guard report is Json::Object(fields) else { @env.exit(70) }
  if fields.get("status") != Some(Json::string("PASS")) {
    @env.exit(2)
  }
}
