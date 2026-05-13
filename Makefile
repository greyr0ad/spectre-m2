CC      = clang
CFLAGS  = -O2 -Wall -Wextra -arch arm64
LDFLAGS = -lpthread
BUILD   = build

.PHONY: all clean tools minimal-prfm-signal two-hop same-process-page-oracle \
        separate-victim-page-oracle separate-victim-fullbyte run-minimal \
        run-page-oracle run-fullbyte run-two-hop

all: tools minimal-prfm-signal two-hop same-process-page-oracle \
     separate-victim-page-oracle separate-victim-fullbyte

$(BUILD):
	mkdir -p $(BUILD)

tools: $(BUILD)/flush_reload_channel $(BUILD)/probe_array_calibration

minimal-prfm-signal: $(BUILD)/minimal_prfm_signal
two-hop: $(BUILD)/same_process_two_hop_read
same-process-page-oracle: $(BUILD)/same_process_page_oracle
separate-victim-page-oracle: $(BUILD)/separate_victim_page_oracle
separate-victim-fullbyte: $(BUILD)/separate_victim_fullbyte

$(BUILD)/flush_reload_channel: tools/flush_reload_channel.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/probe_array_calibration: tools/probe_array_calibration.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/minimal_prfm_signal: demos/minimal_prfm_signal.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/same_process_two_hop_read: demos/same_process_two_hop_read.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/same_process_page_oracle: demos/same_process_page_oracle.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD)/separate_victim_page_oracle: demos/separate_victim_page_oracle.c demos/victim_page_oracle.c demos/victim_page_oracle.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ demos/separate_victim_page_oracle.c demos/victim_page_oracle.c $(LDFLAGS)

$(BUILD)/separate_victim_fullbyte: demos/separate_victim_fullbyte.c demos/victim_fullbyte.c demos/victim_fullbyte.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ demos/separate_victim_fullbyte.c demos/victim_fullbyte.c $(LDFLAGS)

run-minimal: $(BUILD)/minimal_prfm_signal
	./$(BUILD)/minimal_prfm_signal

run-page-oracle: $(BUILD)/separate_victim_page_oracle
	./scripts/run_separate_victim_page_oracle.sh

run-fullbyte: $(BUILD)/separate_victim_fullbyte
	./scripts/run_separate_victim_fullbyte.sh

run-two-hop: $(BUILD)/same_process_two_hop_read
	./$(BUILD)/same_process_two_hop_read

clean:
	rm -rf $(BUILD)
