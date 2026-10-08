"use client";

import { useState } from "react";
import { Button, DateField, DateRangePicker, Label, Popover, RangeCalendar } from "@heroui/react";
import { CalendarDate, getDayOfWeek, today } from "@internationalized/date";
import { CalendarDays } from "lucide-react";

export type DashboardPeriod = { start: string; end: string; label: string; firstDay: CalendarDate; lastDay: CalendarDate };
type Preset = "all" | "day" | "week" | "month" | "year" | "custom";
type DateRange = { start: CalendarDate; end: CalendarDate };
const timeZone = "America/Sao_Paulo";
const dateLabel = new Intl.DateTimeFormat("pt-BR", { day: "2-digit", month: "short", year: "numeric", timeZone });
const options: { value: Preset; label: string }[] = [
  { value: "all", label: "Todos" },
  { value: "day", label: "Hoje" },
  { value: "week", label: "Esta semana" },
  { value: "month", label: "Este mês" },
  { value: "year", label: "Este ano" },
  { value: "custom", label: "Personalizado" },
];

function period(firstDay: CalendarDate, lastDay: CalendarDate): DashboardPeriod {
  return {
    start: firstDay.toDate(timeZone).toISOString(),
    end: lastDay.add({ days: 1 }).toDate(timeZone).toISOString(),
    label: `${dateLabel.format(firstDay.toDate(timeZone))} – ${dateLabel.format(lastDay.toDate(timeZone))}`,
    firstDay, lastDay,
  };
}

function presetRange(preset: Exclude<Preset, "all" | "custom">, anchor: CalendarDate): DateRange {
  if (preset === "day") return { start: anchor, end: anchor };
  if (preset === "week") {
    const start = anchor.subtract({ days: getDayOfWeek(anchor, "en-GB") });
    return { start, end: start.add({ days: 6 }) };
  }
  if (preset === "month") {
    const start = anchor.set({ day: 1 });
    return { start, end: start.add({ months: 1 }).subtract({ days: 1 }) };
  }
  const start = anchor.set({ month: 1, day: 1 });
  return { start, end: start.add({ years: 1 }).subtract({ days: 1 }) };
}

export function DashboardPeriodFilter({ onChange }: { onChange: (value: DashboardPeriod | null) => void }) {
  const [open, setOpen] = useState(false);
  const [appliedPreset, setAppliedPreset] = useState<Preset>("all");
  const [appliedRange, setAppliedRange] = useState<DateRange | null>(null);
  const [draftPreset, setDraftPreset] = useState<Preset>("all");
  const [draftRange, setDraftRange] = useState<DateRange | null>(null);
  const current = today(timeZone);
  const draftInvalid = draftPreset === "custom" && draftRange != null && (
    draftRange.end.compare(draftRange.start) < 0 ||
    draftRange.end.compare(draftRange.start.add({ years: 1 })) > 0 ||
    draftRange.end.compare(current) > 0
  );

  function changeOpen(next: boolean) {
    if (next) {
      setDraftPreset(appliedPreset);
      setDraftRange(appliedRange);
    }
    setOpen(next);
  }

  function selectPreset(value: Preset) {
    setDraftPreset(value);
    setDraftRange(value === "all" ? null : value === "custom"
      ? draftRange ?? { start: current.subtract({ days: 29 }), end: current }
      : presetRange(value, current));
  }

  function apply() {
    if (draftInvalid || (draftPreset !== "all" && !draftRange)) return;
    setAppliedPreset(draftPreset);
    setAppliedRange(draftRange);
    onChange(draftPreset === "all" || !draftRange ? null : period(draftRange.start, draftRange.end));
    setOpen(false);
  }

  const appliedLabel = appliedPreset === "all" ? "Todos os períodos" : appliedRange
    ? `${appliedPreset === "custom" ? "Personalizado" : options.find((option) => option.value === appliedPreset)?.label} · ${period(appliedRange.start, appliedRange.end).label}`
    : "Todos os períodos";

  return <div className="dashboard-period-compact"><Popover isOpen={open} onOpenChange={changeOpen}>
    <Button variant="secondary" className="dashboard-period-trigger" aria-label={`Filtrar por data: ${appliedLabel}`}>
      <CalendarDays size={16} aria-hidden="true" /><span>{appliedLabel}</span>
    </Button>
    <Popover.Content placement="bottom end" offset={8} className="dashboard-period-popover">
      <Popover.Dialog className="dashboard-period-panel" aria-label="Filtrar por período">
        <Popover.Heading>Filtrar por período</Popover.Heading>
        <p className="dashboard-period-help">Mostra vulnerabilidades ainda ativas pela primeira detecção. Correções usam a data de resolução.</p>
        <div className="dashboard-period-presets" role="group" aria-label="Atalhos de período">
          {options.map(({ value, label }) => <Button key={value} size="sm" variant={draftPreset === value ? "primary" : "secondary"} aria-pressed={draftPreset === value} onPress={() => selectPreset(value)}>{label}</Button>)}
        </div>
        <DateRangePicker value={draftRange} onChange={(value) => {
          setDraftPreset("custom");
          setDraftRange(value ? { start: value.start as CalendarDate, end: value.end as CalendarDate } : null);
        }} isInvalid={draftInvalid} shouldForceLeadingZeros>
          <Label>Intervalo personalizado</Label>
          <DateField.Group fullWidth className="dashboard-period-date-group">
            <DateField.Input slot="start">{(segment) => <DateField.Segment segment={segment} />}</DateField.Input>
            <DateRangePicker.RangeSeparator />
            <DateField.Input slot="end">{(segment) => <DateField.Segment segment={segment} />}</DateField.Input>
            <DateField.Suffix><DateRangePicker.Trigger><DateRangePicker.TriggerIndicator /></DateRangePicker.Trigger></DateField.Suffix>
          </DateField.Group>
          <DateRangePicker.Popover className="dashboard-period-calendar-popover"><RangeCalendar aria-label="Selecionar intervalo do dashboard">
            <RangeCalendar.Header><RangeCalendar.YearPickerTrigger><RangeCalendar.YearPickerTriggerHeading /><RangeCalendar.YearPickerTriggerIndicator /></RangeCalendar.YearPickerTrigger><RangeCalendar.NavButton slot="previous" /><RangeCalendar.NavButton slot="next" /></RangeCalendar.Header>
            <RangeCalendar.Grid><RangeCalendar.GridHeader>{(day) => <RangeCalendar.HeaderCell>{day}</RangeCalendar.HeaderCell>}</RangeCalendar.GridHeader><RangeCalendar.GridBody>{(date) => <RangeCalendar.Cell date={date} />}</RangeCalendar.GridBody></RangeCalendar.Grid>
          </RangeCalendar></DateRangePicker.Popover>
        </DateRangePicker>
        {draftInvalid && <p className="dashboard-period-error" role="alert">Selecione até um ano, sem datas futuras.</p>}
        <div className="dashboard-period-actions"><Button variant="secondary" onPress={() => setOpen(false)}>Cancelar</Button><Button isDisabled={draftInvalid || (draftPreset !== "all" && !draftRange)} onPress={apply}>Aplicar</Button></div>
      </Popover.Dialog>
    </Popover.Content>
  </Popover></div>;
}
