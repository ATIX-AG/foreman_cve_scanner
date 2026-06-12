/* eslint-disable import/no-unresolved */
import { useMemo, useState } from 'react';
import { SortByDirection } from '@patternfly/react-table';

const useSortBy = (initialColumn, sorters, items) => {
  const [sortBy, setSortBy] = useState({
    direction: SortByDirection.desc,
    column: initialColumn,
  });

  const onSort = column => {
    setSortBy(prev => ({
      column,
      direction:
        prev.column === column && prev.direction === SortByDirection.asc
          ? SortByDirection.desc
          : SortByDirection.asc,
    }));
  };

  const sortedItems = useMemo(() => {
    const list = [...items];
    const sorter = sorters[sortBy.column] || sorters[initialColumn];
    list.sort((a, b) => {
      const result = sorter(a, b);
      return sortBy.direction === SortByDirection.asc ? result : -result;
    });
    return list;
  }, [initialColumn, items, sortBy, sorters]);

  return { sortBy, onSort, sortedItems, setSortBy };
};

export default useSortBy;
