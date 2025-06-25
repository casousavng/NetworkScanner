document.addEventListener('DOMContentLoaded', ()=> {
  // Plotly node click → detalhe
  const gd = document.querySelector('#network-graph .plotly-graph-div');
  const detail = document.getElementById('detail');
  if (gd) {
    gd.on('plotly_click', data => {
      const ip = data.points[0].customdata;
      fetch(`/api/device/${ip}`)
        .then(r=>r.json())
        .then(d => {
          let html = `<h5>${d.hostname} (${d.ip})</h5>
                      <p><strong>MAC:</strong> ${d.mac}<br>
                         <strong>Vendor:</strong> ${d.vendor}<br>
                         <strong>Último scan:</strong> ${d.last_seen}</p>
                      <h6>Portas</h6><ul>`;
          d.ports.forEach(p => {
            html += `<li>${p.port} – ${p.service} ${p.version}<ul>`;
            if (p.cves.length) {
              p.cves.forEach(c => {
                html += `<li><strong>${c.id}</strong>: ${c.description}</li>`;
              });
            } else {
              html += `<li>Sem CVEs encontradas.</li>`;
            }
            html += `</ul></li>`;
          });
          html += `</ul>`;
          detail.innerHTML = html;
          detail.style.display = 'block';
        });
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    const gd = document.getElementById('network-graph');
    if (gd && typeof Plotly !== 'undefined') {
      Plotly.newPlot(gd, plotData, plotLayout).then(() => {
        gd.on('plotly_click', data => {
          const ip = data.points[0].customdata;
          fetch(`/api/device/${ip}`)
            .then(r => r.json())
            .then(d => {
              // Atualiza detalhe do dispositivo
            });
        });
      });
    }
  });

  // Busca + paginação devices
  const table = document.getElementById('tbl-dev');
  if (table) {
    const rows  = Array.from(table.tBodies[0].rows);
    const perPage = 10, pagin = document.getElementById('pagin');
    const search= document.getElementById('search');
    function renderPage(page=1){
      const filtered = rows.filter(r=>
        r.textContent.toLowerCase().includes(search.value.toLowerCase()));
      const total = Math.ceil(filtered.length/perPage);
      pagin.innerHTML = '';
      for(let i=1;i<=total;i++){
        const li = document.createElement('li');
        li.className = 'page-item'+(i===page?' active':'');
        li.innerHTML = `<a class="page-link" href="#">${i}</a>`;
        li.onclick = e=>{ e.preventDefault(); renderPage(i); };
        pagin.append(li);
      }
      rows.forEach(r=> r.style.display='none');
      filtered.slice((page-1)*perPage,page*perPage)
              .forEach(r=> r.style.display='table-row');
    }
    search.addEventListener('input', ()=> renderPage(1));
    renderPage();
  }

  // WebSocket notifications
  var socket = io();
  socket.on('new_scan', data=>{
    alert(data.message);
  });
});
