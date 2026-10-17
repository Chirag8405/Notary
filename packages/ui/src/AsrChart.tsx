import { DEFAULT_GEOMETRY, asrSeries, chartPoints, chartX, chartY } from "./asr";
import type { AsrSeriesInput } from "./asr";

export interface AsrChartProps {
  series: readonly AsrSeriesInput[];
  title?: string;
}

const DASHES = ["none", "6 4", "2 3", "8 3 2 3"] as const;
const STROKES = ["stroke-red-600", "stroke-blue-600", "stroke-green-700", "stroke-neutral-700"];
const Y_TICKS = [0, 0.5, 1] as const;

function dashOf(index: number): string | undefined {
  const dash = DASHES[index % DASHES.length];
  return dash === undefined || dash === "none" ? undefined : dash;
}

function strokeOf(index: number): string {
  return STROKES[index % STROKES.length] ?? "stroke-neutral-700";
}

/** Rounds that get an x label: all of them up to 10 rounds, else 1, multiples of 5 and the last. */
function labelledRounds(maxRound: number): number[] {
  const rounds = Array.from({ length: maxRound }, (_, index) => index + 1);
  if (maxRound <= 10) return rounds;
  return rounds.filter((round) => round === 1 || round % 5 === 0 || round === maxRound);
}

function percent(rate: number): string {
  return `${Math.round(rate * 100)}%`;
}

/** Attack success rate after each round, one dashed line per lane; plain SVG, no chart library. */
export function AsrChart({ series, title }: AsrChartProps) {
  const plotted = series.map(asrSeries);
  const maxRound = Math.max(
    1,
    ...plotted.flatMap((line) => line.points.map((point) => point.round)),
  );
  if (plotted.every((line) => line.points.length === 0)) return <p>No rounds to plot</p>;

  const geometry = DEFAULT_GEOMETRY;
  const axisY = geometry.height - geometry.bottom;
  const axisRight = geometry.width - geometry.right;
  const rounds = Array.from({ length: maxRound }, (_, index) => index + 1);
  const labelled = new Set(labelledRounds(maxRound));

  return (
    <div className="flex flex-col gap-2">
      <svg
        role="img"
        aria-label={title ?? "Attack success rate per round"}
        viewBox={`0 0 ${geometry.width} ${geometry.height}`}
        className="w-full"
      >
        {Y_TICKS.map((tick) => (
          <g key={tick}>
            <line
              x1={geometry.left}
              x2={axisRight}
              y1={chartY(tick, geometry)}
              y2={chartY(tick, geometry)}
              className="stroke-neutral-200"
            />
            <text
              data-axis="y"
              x={geometry.left - 6}
              y={chartY(tick, geometry)}
              textAnchor="end"
              dominantBaseline="middle"
              className="fill-neutral-600 text-[10px]"
            >
              {percent(tick)}
            </text>
          </g>
        ))}
        <line
          x1={geometry.left}
          x2={axisRight}
          y1={axisY}
          y2={axisY}
          className="stroke-neutral-400"
        />
        {rounds.map((round) => (
          <g key={round}>
            <line
              x1={chartX(round, maxRound, geometry)}
              x2={chartX(round, maxRound, geometry)}
              y1={axisY}
              y2={axisY + 4}
              className="stroke-neutral-400"
            />
            {labelled.has(round) ? (
              <text
                data-axis="x"
                x={chartX(round, maxRound, geometry)}
                y={axisY + 16}
                textAnchor="middle"
                className="fill-neutral-600 text-[10px]"
              >
                {round}
              </text>
            ) : null}
          </g>
        ))}
        {plotted.map((line, index) => {
          const coordinates = chartPoints(line, maxRound, geometry);
          return (
            <g key={index}>
              <polyline
                data-series={line.label}
                points={coordinates.map(({ x, y }) => `${x},${y}`).join(" ")}
                fill="none"
                strokeWidth={2}
                strokeDasharray={dashOf(index)}
                className={strokeOf(index)}
              />
              {coordinates.map(({ x, y }, pointIndex) => (
                <circle
                  key={pointIndex}
                  data-point=""
                  cx={x}
                  cy={y}
                  r={3}
                  className={`fill-white ${strokeOf(index)}`}
                />
              ))}
            </g>
          );
        })}
      </svg>
      <ul aria-label="Legend" className="flex flex-wrap gap-4 text-sm">
        {plotted.map((line, index) => (
          <li key={index} className="flex items-center gap-2">
            <svg width={24} height={8} aria-hidden="true">
              <line
                x1={0}
                x2={24}
                y1={4}
                y2={4}
                strokeWidth={2}
                strokeDasharray={dashOf(index)}
                className={strokeOf(index)}
              />
            </svg>
            <span>{line.label}</span>
          </li>
        ))}
      </ul>
      <table className="sr-only">
        <caption>{title ?? "Attack success rate per round"}</caption>
        <thead>
          <tr>
            <th scope="col">Lane</th>
            <th scope="col">Round</th>
            <th scope="col">Attack success rate</th>
          </tr>
        </thead>
        <tbody>
          {plotted.flatMap((line, index) =>
            line.points.map((point) => (
              <tr key={`${index}-${point.round}`}>
                <th scope="row">{line.label}</th>
                <td>{point.round}</td>
                <td>{percent(point.rate)}</td>
              </tr>
            )),
          )}
        </tbody>
      </table>
    </div>
  );
}
