(function() {
  const QuickPoll = React.createClass({
    getInitialState: function() {
      return {
        current: ''
      };
    },
    UpdateSelectedOption(e) {
      e.stopPropagation();
      e.preventDefault();
      console.log(e);
      console.log(e.target);
      console.log(e.target.value);
      chrome.runtime.sendMessage({
        target: 'real_time',
        query: 'quickPollUpdate',
        groupId: this.props.groupId,
        selection: e.target.value
      }, () => {
        this.props.selectedOption = e.target.value;
      });
    },
    renderSelect() {
      const elements = [
        React.createElement(
          'option',
          {
            key: `qp-${this.props.groupId}-select-empty`,
            selected: (this.state.current === ''),
            className: '',
            value: ''
          },
          ''
        )
      ];
      if (Array.isArray(this.props.options)) {
        this.props.options.forEach((opt) => {
          elements.push(
            React.createElement(
              'option',
              {
                key: `qp-${this.props.groupId}-select-${opt}`,
                selected: (this.props.selectedOption === opt),
                className: '',
                value: opt
              },
              opt
            )
          );
        });
      }
      return React.createElement(
        'select',
        {
          key: `qp-${this.props.groupId}-select`,
          className: 'QuickPoll-Select',
          onChange: this.UpdateSelectedOption
        },
        elements
      );
    },
    render: function() {
      const elements = [];
      elements.push(
        React.createElement(
          'h3',
          {
            key: `qp-${this.props.groupId}-h3`,
            className: '',
          },
          this.props.groupName
        )
      );
      elements.push(
        this.renderSelect.call(this)
      );
      console.log(elements);
      return React.createElement(
        'div',
        {key: `qp-${this.props.groupId}`, className: 'QuickPoll'},
        elements
      );
    }
  });
  const MainMenu = React.createClass({
    getInitialState: function() {
      const self = this;
      chrome.runtime.sendMessage({target: 'real_time', query: 'getState'}, (response) => {
        console.log(response);
        const stateUpdate = {
          hpActive: response.hpActive,
          hpEnabled: response.hpEnabled
        };
        if (response.currentState) {
          stateUpdate.current = response.currentState;
        }
        if (Array.isArray(response.groups)) {
          stateUpdate.groups = response.groups;
        }
        self.setState(stateUpdate);
      });
      return {
        current: 'working'
      };
    },
    updateCurrent: function(newState) {
      const self = this;
      chrome.runtime.sendMessage({target: 'real_time', newState: newState}, () => {
        self.setState({
          current: newState
        });
        window.close();
      });

    },
    render: function() {
      const elements = [];

      console.log(this.state);

      if (this.state.hpActive === true) {
        elements.push(React.createElement('div', {key: 'pass', className: `btn btn-pass`}, 'Active Pass'));
      } else {
        // React.createElement('div', {key: 'current-state', className: 'btn'}, this.state.current),
        elements.push(React.createElement('div', {key: 'working', className: `btn btn-working ${this.state.current === 'working' ? 'selected' : ''}`, onClick: this.updateCurrent.bind(null, 'working')}, 'Working'));
        elements.push(React.createElement('div', {key: 'need-help', className: `btn btn-needhelp ${this.state.current === 'need help' ? 'selected' : ''}`, onClick: this.updateCurrent.bind(null, 'need help')}, 'Need Help'));
        elements.push(React.createElement('div', {key: 'done', className: `btn btn-done ${this.state.current === 'done' ? 'selected' : ''}`, onClick: this.updateCurrent.bind(null, 'done')}, 'Done'));

        // if (Array.isArray(this.state.groups)) {
        //   this.state.groups.forEach((group) => {
        //     if (typeof(group.quickPoll) === 'object' && Object.keys(group.quickPoll).length > 1) {
        //       elements.push(
        //         React.createElement(
        //           QuickPoll,
        //           {
        //             key: `group-${group.id}`,
        //             groupId: group.id,
        //             groupName: group.id,
        //             options: group.quickPoll.options,
        //             selectedOption: group.quickPoll.selectedOption
        //           }
        //         )
        //       );
        //     }
        //   });
        // }

        if (this.state.hpEnabled === true) {
          elements.push(React.createElement('div', {key: 'separator', className: 'separator'}));
          elements.push(React.createElement('div', {key: 'pass', className: `btn btn-pass ${this.state.current === 'request pass' ? 'selected' : ''}`, onClick: this.updateCurrent.bind(null, 'request pass')}, 'Request Pass'));
        }
      }
  
      return React.createElement(
        'div',
        {className: 'MainMenu'},
        elements
      );
    }
  });

  window.onload = function() {
    React.render(
      React.createElement(MainMenu, {}),
      document.getElementById('menu-content')
    );
  };

}).call(this);
