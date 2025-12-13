const cppData = {
  scenario1: [
    { flags: 'S', payload: "" },
    { flags: 'A', payload: "" },
    { flags: '', payload: "I want root access" }
  ],
  scenario2: [
    { flags: '', payload: "Hello Server" }
  ],
  scenario3: [
    { flags: 'S', payload: "" },
    { flags: 'A', payload: "" },
    { flags: '', payload: "\x90\x90\x90\x90\x90\xcc\xcc" }
  ],
  scenario4: [
    { flags: 'S', payload: "" },
    { flags: 'A', payload: "" },
    { flags: '', payload: "Checking route path..." }
  ],
  scenario5: [
    { flags: 'S', payload: "" },
    { flags: 'A', payload: "" },
    { flags: '', payload: "User: ro" },
    { flags: '', payload: "ot access" }
  ],
  scenario6: [
    { flags: 'S', payload: "" },
    { flags: 'A', payload: "" },
    { flags: '', payload: "<script>var user='root';</script>" }
  ],
};
