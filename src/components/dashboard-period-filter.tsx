"use client";

import { useState } from "react";
import { Button, DateField, DateRangePicker, Label, RangeCalendar } from "@heroui/react";
import { CalendarDate, getDayOfWeek, today } from "@internationalized/date";

export type DashboardPeriod = { start: string; end: string; label: string; firstDay: CalendarDate; lastDay: CalendarDate };
type Preset = "all" | "day" | "week" | "month" | "year" | "custom";
const timeZone = "America/Sao_Paulo";
const dateLabel = new Intl.DateTimeFormat("pt-BR", { day: "2-digit", month: "short", year: "numeric", timeZone });

function range(firstDay: CalendarDate, lastDay: CalendarDate): DashboardPeriod {
  return {
    start: firstDay.toDate(timeZone).toISOString(),
    end: lastDay.add({ days: 1 }).toDate(timeZone).toISOString(),
    label: `${dateLabel.format(firstDay.toDate(timeZone))} – ${dateLabel.format(lastDay.toDate(timeZone))}`,
    firstDay, lastDay,
  };
}

function presetRange(preset: Exclude<Preset, "all" | "custom">, anchor: CalendarDate): DashboardPeriod {
  if (preset === "day") return range(anchor, anchor);
  if (preset === "week") {
    const start = anchor.subtract({ days: getDayOfWeek(anchor, "en-GB") });
    return range(start, start.add({ days: 6 }));
  }
  if (preset === "month") {
    const start = anchor.set({ day: 1 });
    return range(start, start.add({ months: 1 }).subtract({ days: 1 }));
  }
  const start = anchor.set({ month: 1, day: 1 });
  return range(start, start.add({ years: 1 }).subtract({ days: 1 }));
}

export function DashboardPeriodFilter({ onChange }: { onChange: (value: DashboardPeriod | null) => void }) {
  const [preset, setPreset] = useState<Preset>("all");
  const [anchor, setAnchor] = useState(() => today(timeZone));
  const [custom, setCustom] = useState<{ start: CalendarDate; end: CalendarDate } | null>(null);
  const current = today(timeZone);
  const selected = preset === "all" ? null : preset === "custom" ? custom && range(custom.start, custom.end) : presetRange(preset, anchor);
  const canNext = preset !== "all" && preset !== "custom" && anchor.compare(current) < 0;

  function select(next: Preset) {
    setPreset(next);
    if (next === "all") onChange(null);
    else if (next === "custom") {
      const selected = custom ?? { start: current.subtract({ days: 29 }), end: current };
      setCustom(selected);
      onChange(range(selected.start, selected.end));
    }
    else { setAnchor(current); onChange(presetRange(next, current)); }
  }

  function move(direction: -1 | 1) {
    if (preset === "all" || preset === "custom") return;
    const unit = preset === "day" ? "days" : preset === "week" ? "weeks" : preset === "month" ? "months" : "years";
    const next = direction < 0 ? anchor.subtract({ [unit]: 1 }) : anchor.add({ [unit]: 1 });
    setAnchor(next);
    onChange(presetRange(preset, next));
  }

  return <div className="dashboard-period" aria-label="Filtrar indicadores por data">
    <div className="dashboard-period-main">
      <div><strong>Período</strong><p>Primeira detecção dos achados que continuam ativos.</p></div>
      <div className="dashboard-period-options" role="group" aria-label="Período do dashboard">
        {([ ["all", "Todos"], ["day", "Dia"], ["week", "Semana"], ["month", "Mês"], ["year", "Ano"], ["custom", "Personalizado"] ] as const).map(([value, label]) =>
          <Button key={value} variant={preset === value ? "primary" : "secondary"} aria-pressed={preset === value} onPress={() => select(value)}>{label}</Button>)}
      </div>
    </div>
    {preset !== "all" && <div className="dashboard-period-detail">
      {preset === "custom" ? <DateRangePicker value={custom} onChange={(value) => {
        if (!value) { setCustom(null); onChange(null); return; }
        const start = value.start as CalendarDate;
        const end = value.end as CalendarDate;
        if (end.compare(start) < 0 || end.compare(start.add({ years: 1 })) > 0) return;
        setCustom({ start, end }); onChange(range(start, end));
      }} maxValue={current}>
        <Label>Intervalo personalizado (até um ano)</Label>
        <DateField.Group fullWidth>
          <DateField.Input slot="start">{(segment) => <DateField.Segment segment={segment} />}</DateField.Input>
          <DateRangePicker.RangeSeparator />
          <DateField.Input slot="end">{(segment) => <DateField.Segment segment={segment} />}</DateField.Input>
          <DateField.Suffix><DateRangePicker.Trigger><DateRangePicker.TriggerIndicator /></DateRangePicker.Trigger></DateField.Suffix>
        </DateField.Group>
        <DateRangePicker.Popover><RangeCalendar aria-label="Selecionar intervalo do dashboard">
          <RangeCalendar.Header><RangeCalendar.YearPickerTrigger><RangeCalendar.Heading /><RangeCalendar.YearPickerTriggerIndicator /></RangeCalendar.YearPickerTrigger><RangeCalendar.NavButton slot="previous" /><RangeCalendar.NavButton slot="next" /></RangeCalendar.Header>
          <RangeCalendar.Grid><RangeCalendar.GridHeader>{(day) => <RangeCalendar.HeaderCell>{day}</RangeCalendar.HeaderCell>}</RangeCalendar.GridHeader><RangeCalendar.GridBody>{(date) => <RangeCalendar.Cell date={date} />}</RangeCalendar.GridBody></RangeCalendar.Grid>
        </RangeCalendar></DateRangePicker.Popover>
      </DateRangePicker> : <div className="dashboard-period-navigation">
        <Button variant="secondary" aria-label="Período anterior" onPress={() => move(-1)}>←</Button>
        <strong aria-live="polite">{selected?.label}</strong>
        <Button variant="secondary" aria-label="Próximo período" isDisabled={!canNext} onPress={() => move(1)}>→</Button>
      </div>}
      <span className="dashboard-period-context">Horário de Brasília · correções pela data de resolução</span>
    </div>}
  </div>;
}
