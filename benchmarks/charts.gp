# Renders the BENCHMARKS.md charts from results-x86_64.dat and
# results-aarch64.dat.
#
#     gnuplot -c benchmarks/charts.gp
#
# Both data files have the same rows in the same order; the second column
# groups them and each group becomes one cluster of bars. Requires gnuplot 5.4
# or newer.

set datafile commentschars "#"
x86_data = "benchmarks/results-x86_64.dat"
arm_data = "benchmarks/results-aarch64.dat"
x86_name = "Intel Xeon 6975P-C"
arm_name = "Arm Neoverse V3"

dryoc_color = "#e8471c"
sodium_color = "#7a7a7a"
x86_color = "#2f6fb3"
arm_color = "#e8471c"

# Column helpers: throughput in MB/s (bytes per ns is GB/s) and the
# dryoc/libsodium speedup.
mbps(bytes, ns) = 1000.0 * bytes / ns
speedup(dryoc_ns, sodium_ns) = sodium_ns / dryoc_ns

set style fill solid 1.0 border lt -1
set style histogram clustered gap 1
set style data histograms
set boxwidth 0.9
set grid ytics lc rgb "#d0d0d0" lw 1
set border 3
set tics nomirror out
set xtics scale 0
set bmargin 5

# Cluster titles placed under the x axis: rows 0-3 Poly1305, 4-7 Secretbox,
# 8-9 Argon2id, 10-11 BLAKE2b.
group_labels(y) = sprintf("set label 1 'Poly1305' at 1.5,%s center front; \
set label 2 'XSalsa20-Poly1305 secretbox' at 5.5,%s center front; \
set label 3 'Argon2id' at 8.5,%s center front; \
set label 4 'BLAKE2b' at 10.5,%s center front", y, y, y, y)

# SVG output is resolution independent; the size only sets the aspect ratio
# and the font-to-plot proportions. The generic font family lets every
# platform substitute its own sans-serif instead of falling back silently.
set terminal svg size 960,520 dynamic font "sans-serif,13" background rgb "white"

# --- Speedup over libsodium, both machines --------------------------------------

set output "benchmarks/speedup.svg"

set title "dryoc speedup over libsodium 1.0.18 (higher is better)\n{/*0.8 single thread, -Ctarget-cpu=native}"
set ylabel "throughput ratio, dryoc / libsodium"
set yrange [0:6.6]
set ytics 1
set arrow 1 from -0.5,1 to 11.5,1 nohead lc rgb "#303030" dt 2 lw 1.5 front
eval group_labels("graph -0.14")
set key top left reverse Left samplen 2 spacing 1.3

# Two series per cluster: each bar is a third of the cluster wide, centred a
# sixth either side of the cluster centre.
plot x86_data using (speedup($4,$5)):xtic(1) lc rgb x86_color title x86_name, \
     arm_data using (speedup($4,$5)) lc rgb arm_color title arm_name, \
     x86_data using ($0-1.0/6):(speedup($4,$5)):(sprintf("%.2fx", speedup($4,$5))) \
          with labels offset 0,0.6 font ",9" notitle, \
     arm_data using ($0+1.0/6):(speedup($4,$5)):(sprintf("%.2fx", speedup($4,$5))) \
          with labels offset 0,0.6 font ",9" notitle, \
     keyentry with lines lc rgb "#303030" dt 2 lw 1.5 title "libsodium = 1.0x"

unset arrow 1


# --- Absolute throughput, one chart per machine ---------------------------------

set ylabel "MB/s"
set logscale y 10
set yrange [90:40000]
set ytics ("100" 100, "1,000" 1000, "10,000" 10000)
set mytics 10
set key top left reverse Left samplen 1.5 spacing 1.3
eval group_labels("graph -0.14")

do for [m=1:2] {
    data = (m == 1) ? x86_data : arm_data
    name = (m == 1) ? x86_name : arm_name
    set output sprintf("benchmarks/throughput-%s.svg", (m == 1) ? "x86_64" : "aarch64")
    set title sprintf("Single-thread throughput, dryoc vs libsodium 1.0.18\n{/*0.8 %s, -Ctarget-cpu=native; log scale}", name)
    plot data using (mbps($3,$4)):xtic(1) lc rgb dryoc_color title "dryoc", \
         data using (mbps($3,$5)) lc rgb sodium_color title "libsodium"
}
